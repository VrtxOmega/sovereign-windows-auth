#include <windows.h>
#include <shellapi.h>
#include <atomic>
#include <algorithm>
#include <cwctype>
#include <string>
#include <thread>
#include <vector>
#include <stdexcept>

namespace {
constexpr UINT Finished=WM_APP+1;
constexpr int Check=101,Restore=102,Restart=103,Close=104,Targets=105;
HWND statusBox=nullptr,targetBox=nullptr;
HFONT font=nullptr;
std::atomic<bool> busy=false;
std::wstring helper,verifiedWindows,verifiedKey;
struct Result { DWORD exit=1; std::wstring text,windows,key; bool restoration=false; };
bool pe() {
 HKEY key=nullptr;
 const auto status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\MiniNT",0,KEY_READ,&key);
 if(key) RegCloseKey(key);
 return status==ERROR_SUCCESS;
}
std::wstring widen(const std::string& text) {
 if(text.empty()) return {};
 const int length=MultiByteToWideChar(CP_UTF8,0,text.data(),static_cast<int>(text.size()),nullptr,0);
 std::wstring result(static_cast<size_t>(length),L'\0');
 MultiByteToWideChar(CP_UTF8,0,text.data(),static_cast<int>(text.size()),result.data(),length);
 return result;
}
std::wstring keyPath() {
 wchar_t drives[512]{};
 GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)),drives);
 std::wstring found;
 for(const wchar_t* drive=drives;*drive;drive+=wcslen(drive)+1) {
  if(GetDriveTypeW(drive)!=DRIVE_REMOVABLE) continue;
  const auto path=std::wstring(drive)+L"SovereignRecovery\\recovery.key";
  if(GetFileAttributesW(path.c_str())==INVALID_FILE_ATTRIBUTES) continue;
  if(!found.empty()) throw std::runtime_error("More than one recovery credential is connected. Leave only the recovery USB you want to use.");
  found=path;
 }
 if(found.empty()) throw std::runtime_error("Insert your paired recovery USB, then select Check recovery USB.");
 return found;
}
Result runTool(const std::wstring& arguments) {
 Result result;
 HANDLE read=nullptr,write=nullptr;
 SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
 if(!CreatePipe(&read,&write,&attributes,0)) throw std::runtime_error("Cannot open the recovery output channel.");
 if(!SetHandleInformation(read,HANDLE_FLAG_INHERIT,0)) { CloseHandle(read);CloseHandle(write);throw std::runtime_error("Cannot protect the recovery output channel."); }
 STARTUPINFOW startup{};startup.cb=sizeof(startup);startup.dwFlags=STARTF_USESTDHANDLES;
 startup.hStdOutput=write;startup.hStdError=write;startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
 PROCESS_INFORMATION process{};
 auto command=L"\""+helper+L"\" "+arguments;
 const BOOL started=CreateProcessW(helper.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process);
 CloseHandle(write);
 if(!started) { CloseHandle(read);throw std::runtime_error("The recovery program could not start. Check the recovery media."); }
 CloseHandle(process.hThread);
 std::string output;
 char block[1024]{};DWORD count=0;
 while(ReadFile(read,block,sizeof(block),&count,nullptr)&&count) {
  if(output.size()<16384) output.append(block,std::min<size_t>(count,16384-output.size()));
 }
 CloseHandle(read);
 WaitForSingleObject(process.hProcess,INFINITE);
 GetExitCodeProcess(process.hProcess,&result.exit);CloseHandle(process.hProcess);
 result.text=widen(output);
 return result;
}
HWND control(HWND window,const wchar_t* type,const wchar_t* text,DWORD style,int x,int y,int width,int height,int id=0) {
 HWND child=CreateWindowExW(0,type,text,WS_CHILD|WS_VISIBLE|style,x,y,width,height,window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
 SendMessageW(child,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
 return child;
}
void enable(HWND window,bool available) {
 EnableWindow(GetDlgItem(window,Check),available);
 EnableWindow(GetDlgItem(window,Targets),available);
 EnableWindow(GetDlgItem(window,Restart),available);
 EnableWindow(GetDlgItem(window,Close),available);
 EnableWindow(GetDlgItem(window,Restore),available&&!verifiedWindows.empty());
 RedrawWindow(window,nullptr,nullptr,RDW_INVALIDATE|RDW_ERASE|RDW_ALLCHILDREN|RDW_UPDATENOW);
}
void start(HWND window,bool restoration) {
 if(busy.exchange(true)) return;
 try {
  const auto selected=SendMessageW(targetBox,CB_GETCURSEL,0,0);
  if(selected==CB_ERR) throw std::runtime_error("Choose a Windows installation. If none is listed, its drive may be locked or need a storage driver.");
  wchar_t target[32]{};SendMessageW(targetBox,CB_GETLBTEXT,selected,reinterpret_cast<LPARAM>(target));
  const std::wstring windows(target),key=keyPath();
  if(restoration&&(windows!=verifiedWindows||key!=verifiedKey)) throw std::runtime_error("Check this Windows installation and recovery USB first.");
  if(restoration&&MessageBoxW(window,L"Restore the normal Windows PIN sign-in screen?\n\nYour PIN and YubiKey enrollments will be kept. You will need your normal PIN after restarting.",L"Restore PIN sign-in",MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)!=IDYES) {busy=false;return;}
  enable(window,false);
  SetWindowTextW(statusBox,restoration ? L"Restoring sign-in. Keep the USB connected and wait for the result." : L"Checking the USB against this Windows installation. No sign-in settings are being changed.");
  std::thread([window,windows,key,restoration] {
   auto result=new Result;
   try { *result=runTool(std::wstring(restoration?L"--remove-filter":L"--inspect-usb")+L" \""+windows+L"\" \""+key+L"\""); }
   catch(const std::exception& error) {result->text=widen(error.what());}
   result->windows=windows;result->key=key;result->restoration=restoration;
   if(!PostMessageW(window,Finished,0,reinterpret_cast<LPARAM>(result))) delete result;
  }).detach();
 } catch(const std::exception& error) {busy=false;SetWindowTextW(statusBox,widen(error.what()).c_str());enable(window,true);}
}
void reboot(bool shutdown) {
 wchar_t system[MAX_PATH]{};GetSystemDirectoryW(system,MAX_PATH);
 ShellExecuteW(nullptr,L"open",(std::wstring(system)+L"\\wpeutil.exe").c_str(),shutdown?L"shutdown":L"reboot",nullptr,SW_HIDE);
}
LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam) {
 switch(message) {
 case WM_CREATE: {
  // The standard PE image includes Tahoma, but can omit regular Segoe UI.
  font=CreateFontW(-18,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"Tahoma");
  control(window,L"STATIC",L"Sovereign Recovery",0,28,20,640,32);
  control(window,L"STATIC",L"Use your paired USB to restore the normal Windows PIN sign-in screen.\nYour Windows PIN and YubiKey enrollments will be kept.",0,28,60,670,56);
  control(window,L"STATIC",L"Windows installation",0,28,131,200,25);
  targetBox=control(window,L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP,235,126,280,160,Targets);
  wchar_t drives[512]{},running[MAX_PATH]{};GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)),drives);GetWindowsDirectoryW(running,MAX_PATH);
  int count=0;
  for(const wchar_t* drive=drives;*drive;drive+=wcslen(drive)+1) {
   if(GetDriveTypeW(drive)!=DRIVE_FIXED||towupper(drive[0])==towupper(running[0])) continue;
   const auto root=std::wstring(drive)+L"Windows";
   if(GetFileAttributesW((root+L"\\System32\\config\\SOFTWARE").c_str())==INVALID_FILE_ATTRIBUTES) continue;
   if(GetFileAttributesW((root+L"\\System32\\ntoskrnl.exe").c_str())==INVALID_FILE_ATTRIBUTES) continue;
   SendMessageW(targetBox,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(root.c_str()));++count;
  }
  if(count==1) SendMessageW(targetBox,CB_SETCURSEL,0,0);
  statusBox=control(window,L"EDIT",L"Select Check recovery USB. Recovery does not reset or reveal your PIN.",ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|WS_BORDER,28,175,670,207);
  control(window,L"BUTTON",L"Check recovery USB",WS_TABSTOP|BS_DEFPUSHBUTTON,28,400,220,42,Check);
  control(window,L"BUTTON",L"Restore PIN sign-in",WS_TABSTOP,266,400,220,42,Restore);
  control(window,L"BUTTON",L"Restart",WS_TABSTOP,504,400,194,42,Restart);
  control(window,L"BUTTON",L"Shut down",WS_TABSTOP,504,461,194,36,Close);
  control(window,L"STATIC",L"Keep this USB separate from your laptop afterward.",0,28,462,455,45);
  EnableWindow(GetDlgItem(window,Restore),FALSE);
  return 0;
 }
 case WM_COMMAND:
  if(LOWORD(wparam)==Targets&&HIWORD(wparam)==CBN_SELCHANGE) {verifiedWindows.clear();EnableWindow(GetDlgItem(window,Restore),FALSE);return 0;}
  if(LOWORD(wparam)==Check) {verifiedWindows.clear();start(window,false);return 0;}
  if(LOWORD(wparam)==Restore) {start(window,true);return 0;}
  if(!busy&&LOWORD(wparam)==Restart) {reboot(false);return 0;}
  if(!busy&&LOWORD(wparam)==Close) {reboot(true);return 0;}
  break;
 case Finished: {
  auto result=reinterpret_cast<Result*>(lparam);busy=false;
  if(!result->exit&&!result->restoration) {verifiedWindows=result->windows;verifiedKey=result->key;}
  else verifiedWindows.clear();
  if(!result->exit&&result->restoration) result->text=L"Recovery complete. Select Restart, remove the USB, and use your normal Windows PIN.\r\n\r\n"+result->text;
  SetWindowTextW(statusBox,result->text.c_str());delete result;enable(window,true);return 0;
 }
 case WM_CLOSE: if(!busy) reboot(true);return 0;
 case WM_DESTROY: if(font)DeleteObject(font);PostQuitMessage(0);return 0;
 }
 return DefWindowProcW(window,message,wparam,lparam);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show) {
 if(!pe()) {MessageBoxW(nullptr,L"Boot Sovereign Recovery from the Corsair USB to use this screen. No Windows settings were changed.",L"Sovereign Recovery",MB_OK|MB_ICONINFORMATION);return 1;}
 wchar_t path[32768]{};const auto length=GetModuleFileNameW(nullptr,path,static_cast<DWORD>(std::size(path)));
 if(!length||length>=std::size(path)) return 1;
 helper=std::wstring(path);helper=helper.substr(0,helper.find_last_of(L'\\')+1)+L"swa_filter_recovery.exe";
 WNDCLASSW type{};type.lpfnWndProc=procedure;type.hInstance=instance;type.lpszClassName=L"SovereignRecoveryScreen";type.hCursor=LoadCursorW(nullptr,IDC_ARROW);type.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
 if(!RegisterClassW(&type)) return 1;
 const int x=(GetSystemMetrics(SM_CXSCREEN)-742)/2,y=(GetSystemMetrics(SM_CYSCREEN)-552)/2;
 HWND window=CreateWindowExW(0,type.lpszClassName,L"Sovereign Recovery",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,x,y,742,552,nullptr,nullptr,instance,nullptr);
 if(!window)return 1;
 ShowWindow(window,show);UpdateWindow(window);
 MSG message{};while(GetMessageW(&message,nullptr,0,0)>0) {if(!IsDialogMessageW(window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
 return 0;
}
