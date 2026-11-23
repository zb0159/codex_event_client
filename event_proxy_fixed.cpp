// event_proxy.cpp
// Windows + Libevent TCP forward proxy
// Assumptions:
//   - Libevent 2.1.x built with Windows support
//   - Existing project provides iniFileLoad(), iniGetString(), iniGetInt()
//   - Existing project resources provide IDI_SMALL and optional "TuoPan" menu
//   - XOR(1) transformation is intentionally preserved in both directions.

#include "stdafx.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <wininet.h>
#include <tchar.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "event_proxy.h"
#include "Resource.h"

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/listener.h"
#include "event2/util.h"
#include "event2/thread.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

#pragma warning(disable:4996)

#define WM_IAWENTRAY       (WM_USER + 5)
#define COMMLIB_DBG_FILE   "./log.log"
#define BUF_SIZE           8192
#define MAX_OUTPUT         (512 * 1024)
#define LOW_OUTPUT         (MAX_OUTPUT / 2)
#define CONNECT_TIMEOUT    15

static const char* g_iniFile = "test.conf";

char remote_host[128] = { 0 };
int remote_port = 8089;
char local_host[128] = { 0 };
int local_port = 36356;

static struct event_base* g_base = NULL;
static struct evconnlistener* g_listener = NULL;
static HANDLE g_workerThread = NULL;
static HINSTANCE g_instance = NULL;
static NOTIFYICONDATA g_nid;
static HMENU g_menu = NULL;

// Previous PAC value is restored when this program exits.
static BYTE g_oldPac[2048];
static DWORD g_oldPacSize = sizeof(g_oldPac);
static DWORD g_oldPacType = REG_SZ;
static BOOL g_hadOldPac = FALSE;
static BOOL g_pacBackupValid = FALSE;

struct ProxyConnection
{
    struct bufferevent* client;
    struct bufferevent* upstream;
    struct event* connectTimer;
    BOOL connected;
    BOOL closing;
};

static void LOG(const char* fmt, ...)
{
    FILE* fp = fopen(COMMLIB_DBG_FILE, "a");
    if (!fp)
        return;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);

    fputc('\n', fp);
    fclose(fp);
}

static void pass(char* data, size_t len)
{
    // Preserves the original wire transformation.
    for (size_t i = 0; i < len; ++i)
        data[i] = (char)(data[i] ^ 1);
}

static void notifyInternetSettingsChanged()
{
    InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

    DWORD_PTR result = 0;
    SendMessageTimeout(
        HWND_BROADCAST,
        WM_SETTINGCHANGE,
        0,
        (LPARAM)_T("Internet Settings"),
        SMTO_ABORTIFHUNG,
        5000,
        &result);
}

static int backupPacValue(HKEY hKey)
{
    g_oldPacSize = sizeof(g_oldPac);
    g_oldPacType = REG_SZ;
    g_hadOldPac = FALSE;

    LONG rc = RegQueryValueExA(
        hKey,
        "AutoConfigURL",
        NULL,
        &g_oldPacType,
        g_oldPac,
        &g_oldPacSize);

    if (rc == ERROR_SUCCESS)
    {
        g_hadOldPac = TRUE;
        g_pacBackupValid = TRUE;
        return 0;
    }

    if (rc == ERROR_FILE_NOT_FOUND)
    {
        g_hadOldPac = FALSE;
        g_pacBackupValid = TRUE;
        return 0;
    }

    LOG("RegQueryValueEx(AutoConfigURL) failed: %ld", rc);
    return -1;
}

int write_client_reg()
{
    const char* sub =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(
        HKEY_CURRENT_USER, sub, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);

    if (rc != ERROR_SUCCESS)
    {
        LOG("write_client_reg: RegOpenKeyEx failed: %ld", rc);
        return -1;
    }

    if (backupPacValue(hKey) != 0)
    {
        RegCloseKey(hKey);
        return -1;
    }

    char pacUrl[1024] = { 0 };
    iniGetString("sect1", "serverpac", pacUrl, sizeof(pacUrl),
        "http://222.180.23.212:9097/pac");

    rc = RegSetValueExA(
        hKey,
        "AutoConfigURL",
        0,
        REG_SZ,
        (const BYTE*)pacUrl,
        (DWORD)(strlen(pacUrl) + 1));

    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS)
    {
        LOG("write_client_reg: RegSetValueEx failed: %ld", rc);
        return -1;
    }

    notifyInternetSettingsChanged();
    return 0;
}

int back_reg()
{
    if (!g_pacBackupValid)
        return 0;

    const char* sub =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(
        HKEY_CURRENT_USER, sub, 0, KEY_SET_VALUE, &hKey);

    if (rc != ERROR_SUCCESS)
    {
        LOG("back_reg: RegOpenKeyEx failed: %ld", rc);
        return -1;
    }

    if (g_hadOldPac)
    {
        rc = RegSetValueExA(
            hKey,
            "AutoConfigURL",
            0,
            g_oldPacType,
            g_oldPac,
            g_oldPacSize);
    }
    else
    {
        rc = RegDeleteValueA(hKey, "AutoConfigURL");
        if (rc == ERROR_FILE_NOT_FOUND)
            rc = ERROR_SUCCESS;
    }

    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS)
    {
        LOG("back_reg: restore AutoConfigURL failed: %ld", rc);
        return -1;
    }

    g_pacBackupValid = FALSE;
    notifyInternetSettingsChanged();
    return 0;
}

int write_reg(const char* host, int port, int enable)
{
    if (!host || port < 1 || port > 65535)
        return -1;

    const char* sub =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(
        HKEY_CURRENT_USER, sub, 0, KEY_SET_VALUE, &hKey);

    if (rc != ERROR_SUCCESS)
    {
        LOG("write_reg: RegOpenKeyEx failed: %ld", rc);
        return -1;
    }

    DWORD enabled = enable ? 1 : 0;
    char server[256] = { 0 };

    int n = _snprintf_s(
        server, sizeof(server), _TRUNCATE, "%s:%d", host, port);

    if (n < 0)
    {
        RegCloseKey(hKey);
        LOG("write_reg: proxy server string too long");
        return -1;
    }

    rc = RegSetValueExA(
        hKey, "ProxyEnable", 0, REG_DWORD,
        (const BYTE*)&enabled, sizeof(enabled));

    if (rc == ERROR_SUCCESS)
    {
        rc = RegSetValueExA(
            hKey, "ProxyServer", 0, REG_SZ,
            (const BYTE*)server, (DWORD)(strlen(server) + 1));
    }

    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS)
    {
        LOG("write_reg: RegSetValueEx failed: %ld", rc);
        return -1;
    }

    notifyInternetSettingsChanged();
    return 0;
}

static void closeConnection(struct ProxyConnection* conn)
{
    if (!conn || conn->closing)
        return;

    conn->closing = TRUE;

    if (conn->connectTimer)
    {
        event_del(conn->connectTimer);
        event_free(conn->connectTimer);
        conn->connectTimer = NULL;
    }

    if (conn->client)
    {
        bufferevent_free(conn->client);
        conn->client = NULL;
    }

    if (conn->upstream)
    {
        bufferevent_free(conn->upstream);
        conn->upstream = NULL;
    }

    free(conn);
}

static int transferData(
    struct bufferevent* srcBev,
    struct bufferevent* dstBev)
{
    if (!srcBev || !dstBev)
        return -1;

    struct evbuffer* src = bufferevent_get_input(srcBev);
    struct evbuffer* dst = bufferevent_get_output(dstBev);

    char buffer[BUF_SIZE];

    while (evbuffer_get_length(src) > 0)
    {
        size_t len = evbuffer_get_length(src);
        if (len > sizeof(buffer))
            len = sizeof(buffer);

        ev_ssize_t n = evbuffer_remove(src, buffer, len);
        if (n <= 0)
        {
            LOG("evbuffer_remove failed");
            return -1;
        }

        pass(buffer, (size_t)n);

        if (evbuffer_add(dst, buffer, (size_t)n) < 0)
        {
            LOG("evbuffer_add failed");
            return -1;
        }
    }

    return 0;
}

static void clientReadCallback(struct bufferevent* bev, void* ctx)
{
    ProxyConnection* conn = (ProxyConnection*)ctx;
    if (!conn || conn->closing || !conn->connected)
        return;

    if (transferData(bev, conn->upstream) != 0)
    {
        closeConnection(conn);
        return;
    }

    struct evbuffer* out =
        bufferevent_get_output(conn->upstream);

    if (evbuffer_get_length(out) >= MAX_OUTPUT)
        bufferevent_disable(conn->client, EV_READ);
}

static void upstreamReadCallback(struct bufferevent* bev, void* ctx)
{
    ProxyConnection* conn = (ProxyConnection*)ctx;
    if (!conn || conn->closing || !conn->connected)
        return;

    if (transferData(bev, conn->client) != 0)
    {
        closeConnection(conn);
        return;
    }

    struct evbuffer* out =
        bufferevent_get_output(conn->client);

    if (evbuffer_get_length(out) >= MAX_OUTPUT)
        bufferevent_disable(conn->upstream, EV_READ);
}

static void writeCallback(struct bufferevent* bev, void* ctx)
{
    ProxyConnection* conn = (ProxyConnection*)ctx;
    if (!conn || conn->closing || !conn->connected)
        return;

    // When a destination output queue drains, resume reading from
    // the opposite endpoint.
    size_t queued =
        evbuffer_get_length(bufferevent_get_output(bev));

    if (queued > LOW_OUTPUT)
        return;

    if (bev == conn->upstream && conn->client)
        bufferevent_enable(conn->client, EV_READ);
    else if (bev == conn->client && conn->upstream)
        bufferevent_enable(conn->upstream, EV_READ);
}

static void connectTimeoutCallback(evutil_socket_t, short, void* ctx)
{
    ProxyConnection* conn = (ProxyConnection*)ctx;
    if (!conn || conn->closing || conn->connected)
        return;

    LOG("upstream connect timeout: %s:%d", remote_host, remote_port);
    closeConnection(conn);
}

static void connectionEventCallback(
    struct bufferevent* bev,
    short events,
    void* ctx)
{
    ProxyConnection* conn = (ProxyConnection*)ctx;
    if (!conn || conn->closing)
        return;

    if (events & BEV_EVENT_CONNECTED)
    {
        if (bev != conn->upstream)
            return;

        conn->connected = TRUE;

        if (conn->connectTimer)
        {
            event_del(conn->connectTimer);
            event_free(conn->connectTimer);
            conn->connectTimer = NULL;
        }

        LOG("connected to upstream %s:%d", remote_host, remote_port);

        bufferevent_enable(conn->client, EV_READ | EV_WRITE);
        bufferevent_enable(conn->upstream, EV_READ | EV_WRITE);
        return;
    }

    if (events & BEV_EVENT_TIMEOUT)
        LOG("connection timeout, events=0x%x", events);
    else if (events & BEV_EVENT_ERROR)
        LOG("connection error, socket error=%d", EVUTIL_SOCKET_ERROR());
    else if (events & BEV_EVENT_EOF)
        LOG("connection closed by peer");

    // Close both ends on EOF/error. This avoids leaving half-dead
    // pairs and dangling callback contexts.
    closeConnection(conn);
}

static void acceptCallback(
    struct evconnlistener*,
    evutil_socket_t fd,
    struct sockaddr*,
    int,
    void*)
{
    ProxyConnection* conn =
        (ProxyConnection*)calloc(1, sizeof(ProxyConnection));

    if (!conn)
    {
        evutil_closesocket(fd);
        LOG("calloc ProxyConnection failed");
        return;
    }

    conn->client = bufferevent_socket_new(
        g_base,
        fd,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    if (!conn->client)
    {
        evutil_closesocket(fd);
        free(conn);
        LOG("create client bufferevent failed");
        return;
    }

    conn->upstream = bufferevent_socket_new(
        g_base,
        -1,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    if (!conn->upstream)
    {
        bufferevent_free(conn->client);
        free(conn);
        LOG("create upstream bufferevent failed");
        return;
    }

    bufferevent_setcb(
        conn->client,
        clientReadCallback,
        writeCallback,
        connectionEventCallback,
        conn);

    bufferevent_setcb(
        conn->upstream,
        upstreamReadCallback,
        writeCallback,
        connectionEventCallback,
        conn);

    // The write callback fires when the output queue reaches this
    // low watermark, allowing the opposite read side to resume.
    bufferevent_setwatermark(
        conn->client, EV_WRITE, LOW_OUTPUT, 0);

    bufferevent_setwatermark(
        conn->upstream, EV_WRITE, LOW_OUTPUT, 0);

    conn->connectTimer = evtimer_new(
        g_base, connectTimeoutCallback, conn);

    if (!conn->connectTimer)
    {
        closeConnection(conn);
        LOG("create connect timer failed");
        return;
    }

    struct timeval tv;
    tv.tv_sec = CONNECT_TIMEOUT;
    tv.tv_usec = 0;

    if (evtimer_add(conn->connectTimer, &tv) != 0)
    {
        closeConnection(conn);
        LOG("add connect timer failed");
        return;
    }

    // Do not read client data until the upstream connection succeeds.
    bufferevent_enable(conn->client, EV_WRITE);
    bufferevent_enable(conn->upstream, EV_WRITE);

    if (bufferevent_socket_connect_hostname(
        conn->upstream,
        NULL,
        AF_INET,
        remote_host,
        remote_port) < 0)
    {
        LOG("connect request failed: %s:%d", remote_host, remote_port);
        closeConnection(conn);
        return;
    }
}

static void listenerErrorCallback(struct evconnlistener*, void*)
{
    LOG("listener error: %d", EVUTIL_SOCKET_ERROR());
    if (g_base)
        event_base_loopbreak(g_base);
}

static DWORD WINAPI startProxyThread(LPVOID)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));

    sin.sin_family = AF_INET;
    sin.sin_port = htons((u_short)local_port);

    if (evutil_inet_pton(AF_INET, local_host, &sin.sin_addr) != 1)
    {
        LOG("invalid local address: %s", local_host);
        return 1;
    }

    g_listener = evconnlistener_new_bind(
        g_base,
        acceptCallback,
        NULL,
        LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
        128,
        (struct sockaddr*)&sin,
        sizeof(sin));

    if (!g_listener)
    {
        LOG("create listener failed: %d", EVUTIL_SOCKET_ERROR());
        return 1;
    }

    evconnlistener_set_error_cb(g_listener, listenerErrorCallback);

    LOG("proxy listening on %s:%d -> %s:%d",
        local_host, local_port, remote_host, remote_port);

    int rc = event_base_dispatch(g_base);
    LOG("event_base_dispatch returned: %d", rc);

    evconnlistener_free(g_listener);
    g_listener = NULL;

    return 0;
}

static void intconf()
{
    iniFileLoad(g_iniFile);

    iniGetString(
        "sect1", "local_ip",
        local_host, sizeof(local_host), "127.0.0.1");

    local_port = iniGetInt("sect1", "local_port", 36356);

    iniGetString(
        "sect1", "remote_ip",
        remote_host, sizeof(remote_host), "222.180.23.212");

    remote_port = iniGetInt("sect1", "remote_port", 8089);

    if (local_port < 1 || local_port > 65535)
        local_port = 36356;

    if (remote_port < 1 || remote_port > 65535)
        remote_port = 8089;
}

static void cleanupProxy()
{
    if (g_base)
        event_base_loopbreak(g_base);

    if (g_workerThread)
    {
        WaitForSingleObject(g_workerThread, INFINITE);
        CloseHandle(g_workerThread);
        g_workerThread = NULL;
    }

    if (g_base)
    {
        event_base_free(g_base);
        g_base = NULL;
    }
}

LRESULT CALLBACK MainWndProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        write_client_reg();

        g_workerThread = CreateThread(
            NULL, 0, startProxyThread, NULL, 0, NULL);

        if (!g_workerThread)
        {
            LOG("CreateThread failed: %lu", GetLastError());
            back_reg();
            return -1;
        }

        g_nid.cbSize = sizeof(g_nid);
        g_nid.hWnd = hwnd;
        g_nid.uID = IDI_SMALL;
        g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        g_nid.uCallbackMessage = WM_IAWENTRAY;
        g_nid.hIcon = LoadIcon(g_instance, MAKEINTRESOURCE(IDI_SMALL));
        _tcscpy_s(g_nid.szTip, _countof(g_nid.szTip), _T("proxy service"));

        Shell_NotifyIcon(NIM_ADD, &g_nid);

        g_menu = LoadMenu(g_instance, _T("TuoPan"));
        if (g_menu)
            g_menu = GetSubMenu(g_menu, 0);

        return 0;
    }

    case WM_IAWENTRAY:
        if (wParam == IDI_SMALL && lParam == WM_RBUTTONDOWN)
        {
            if (MessageBox(
                hwnd,
                _T("确定要退出吗？退出后代理服务将停止运行。"),
                _T("proxy service"),
                MB_OKCANCEL | MB_ICONQUESTION) == IDOK)
            {
                DestroyWindow(hwnd);
            }
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        Shell_NotifyIcon(NIM_DELETE, &g_nid);

        // Stop the event loop and wait for the worker before freeing
        // the event base. Thread support was initialized before base creation.
        cleanupProxy();

        back_reg();
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProc(hwnd, message, wParam, lParam);
}

int APIENTRY _tWinMain(
    HINSTANCE hInstance,
    HINSTANCE,
    LPTSTR,
    int nCmdShow)
{
    g_instance = hInstance;

    intconf();

    WSADATA wsaData;
    int wsaRc = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaRc != 0)
    {
        MessageBox(NULL, _T("WSAStartup failed"), _T("Error"), MB_OK | MB_ICONERROR);
        return -1;
    }

    // Must be called before event_base_new() when using Libevent
    // from both the UI thread and the worker thread.
    if (evthread_use_windows_threads() != 0)
    {
        LOG("evthread_use_windows_threads failed");
        WSACleanup();
        return -1;
    }

    g_base = event_base_new();
    if (!g_base)
    {
        LOG("event_base_new failed");
        WSACleanup();
        return -1;
    }

    const TCHAR className[] = _T("MainWClass");

    WNDCLASSEX wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = className;
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wc))
    {
        LOG("RegisterClassEx failed: %lu", GetLastError());
        event_base_free(g_base);
        g_base = NULL;
        WSACleanup();
        return -1;
    }

    HWND hwnd = CreateWindowEx(
        0,
        className,
        _T("proxy service"),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        300,
        200,
        NULL,
        NULL,
        hInstance,
        NULL);

    if (!hwnd)
    {
        LOG("CreateWindowEx failed: %lu", GetLastError());
        event_base_free(g_base);
        g_base = NULL;
        WSACleanup();
        return -1;
    }

    ShowWindow(hwnd, SW_HIDE);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // WM_DESTROY normally performs cleanup. This is a safety net.
    if (g_workerThread || g_base)
        cleanupProxy();

    WSACleanup();
    return (int)msg.wParam;
}
