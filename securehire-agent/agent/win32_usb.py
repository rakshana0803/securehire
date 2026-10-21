"""Windows USB backend: SetupAPI enumeration + WM_DEVICECHANGE notifications (ctypes, no admin rights).

Documented APIs used:
  SetupDiGetClassDevsW / SetupDiEnumDeviceInfo / SetupDiGetDeviceInstanceIdW /
  SetupDiGetDeviceRegistryPropertyW (SPDRP_SERVICE, SPDRP_CLASS) / SetupDiDestroyDeviceInfoList,
  RegisterDeviceNotificationW (DBT_DEVTYP_DEVICEINTERFACE) on a message-only window (HWND_MESSAGE).
Only device metadata is read. Nothing on any device is opened or accessed.

REQUIRES A REAL WINDOWS MACHINE — this module is not exercised by the automated tests, which
use a fake backend with the same interface.
"""
from __future__ import annotations

import ctypes
import logging
import threading
from ctypes import wintypes
from typing import Optional

from .models import UsbDevice
from .usb_monitor import classify_usb_device, parse_vid_pid

log = logging.getLogger("securehire.usb.win32")

setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
HDEVINFO = ctypes.c_void_p
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10
SPDRP_SERVICE = 0x04
SPDRP_CLASS = 0x07
ERROR_NO_MORE_ITEMS = 259

WM_DEVICECHANGE = 0x0219
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
HWND_MESSAGE = ctypes.c_void_p(-3)
DEVICE_NOTIFY_WINDOW_HANDLE = 0x0
DBT_DEVTYP_DEVICEINTERFACE = 0x5


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, s: str) -> "GUID":
        h = s.strip("{}").replace("-", "")
        g = cls()
        g.Data1, g.Data2, g.Data3 = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)
        for i in range(8):
            g.Data4[i] = int(h[16 + 2 * i:18 + 2 * i], 16)
        return g


GUID_DEVINTERFACE_USB_DEVICE = GUID.parse("A5DCBF10-6530-11D2-901F-00C04FB951ED")
GUID_DEVINTERFACE_HID = GUID.parse("4D1E55B2-F16F-11CF-88CB-001111000030")
KSCATEGORY_VIDEO_CAMERA = GUID.parse("E5323777-F976-4F5B-9B55-B94699C46E44")
GUID_DEVINTERFACE_WPD = GUID.parse("6AC27878-A6FA-4155-BA85-F98F491D4F33")


class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("ClassGuid", GUID), ("DevInst", wintypes.DWORD), ("Reserved", ctypes.c_size_t)]


class DEV_BROADCAST_DEVICEINTERFACE_W(ctypes.Structure):
    _fields_ = [("dbcc_size", wintypes.DWORD), ("dbcc_devicetype", wintypes.DWORD), ("dbcc_reserved", wintypes.DWORD),
                ("dbcc_classguid", GUID), ("dbcc_name", ctypes.c_wchar * 1)]


WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]


setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
setupapi.SetupDiGetClassDevsW.restype = HDEVINFO
setupapi.SetupDiEnumDeviceInfo.argtypes = [HDEVINFO, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)]
setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [HDEVINFO, ctypes.POINTER(SP_DEVINFO_DATA), wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
setupapi.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [HDEVINFO, ctypes.POINTER(SP_DEVINFO_DATA), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                                       ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
setupapi.SetupDiGetDeviceRegistryPropertyW.restype = wintypes.BOOL
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [HDEVINFO]
setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
user32.RegisterClassW.restype = wintypes.ATOM
user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
user32.CreateWindowExW.restype = wintypes.HWND
user32.RegisterDeviceNotificationW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD]
user32.RegisterDeviceNotificationW.restype = wintypes.HANDLE
user32.UnregisterDeviceNotification.argtypes = [wintypes.HANDLE]
user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = wintypes.BOOL
user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DispatchMessageW.restype = LRESULT
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DestroyWindow.argtypes = [wintypes.HWND]
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE


def _string_property(hdev, info: SP_DEVINFO_DATA, prop: int) -> Optional[str]:
    buf = ctypes.create_unicode_buffer(512)
    reg_type = wintypes.DWORD()
    if setupapi.SetupDiGetDeviceRegistryPropertyW(hdev, ctypes.byref(info), prop, ctypes.byref(reg_type), buf, ctypes.sizeof(buf), None):
        return buf.value or None
    return None


def _enumerate(guid: GUID, with_props: bool) -> list[tuple[str, Optional[str], Optional[str]]]:
    """[(instance_id, service, setup_class)] for present devices exposing the interface class."""
    hdev = setupapi.SetupDiGetClassDevsW(ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if not hdev or hdev == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    out = []
    try:
        i = 0
        while True:
            info = SP_DEVINFO_DATA()
            info.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            if not setupapi.SetupDiEnumDeviceInfo(hdev, i, ctypes.byref(info)):
                err = ctypes.get_last_error()
                if err == ERROR_NO_MORE_ITEMS:
                    break
                raise ctypes.WinError(err)
            i += 1
            id_buf = ctypes.create_unicode_buffer(512)
            if not setupapi.SetupDiGetDeviceInstanceIdW(hdev, ctypes.byref(info), id_buf, len(id_buf), None):
                continue
            svc = _string_property(hdev, info, SPDRP_SERVICE) if with_props else None
            cls = _string_property(hdev, info, SPDRP_CLASS) if with_props else None
            out.append((id_buf.value.upper(), svc, cls))
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return out


def _vidpids(guid: GUID) -> set[tuple[str, str]]:
    result = set()
    for iid, _, _ in _enumerate(guid, with_props=False):
        vp = parse_vid_pid(iid)
        if vp[0]:
            result.add(vp)  # type: ignore[arg-type]
    return result


class WindowsUsbBackend:
    def __init__(self) -> None:
        self._changed = threading.Event()
        self._closed = threading.Event()
        self._hwnd: Optional[int] = None
        self._thread = threading.Thread(target=self._message_loop, name="securehire-usb-notify", daemon=True)
        self._ready = threading.Event()
        self._thread.start()
        self._ready.wait(3.0)

    # ---- snapshot
    def snapshot(self) -> dict[str, UsbDevice]:
        hid = _vidpids(GUID_DEVINTERFACE_HID)
        cams = _vidpids(KSCATEGORY_VIDEO_CAMERA)
        try:
            wpd = _vidpids(GUID_DEVINTERFACE_WPD)
        except OSError:
            wpd = set()
        devices: dict[str, UsbDevice] = {}
        for iid, svc, cls in _enumerate(GUID_DEVINTERFACE_USB_DEVICE, with_props=True):
            category = classify_usb_device(svc, cls, iid, hid_vidpids=hid, camera_vidpids=cams, portable_vidpids=wpd)
            if category is None:
                continue
            vid, pid = parse_vid_pid(iid)
            devices[iid] = UsbDevice(instance_key=iid, category=category, vendor_id=vid, product_id=pid, device_class=cls, service=svc)
        return devices

    # ---- notifications
    def wait_for_change(self, timeout: float) -> bool:
        fired = self._changed.wait(timeout)
        self._changed.clear()
        return fired

    def _message_loop(self) -> None:
        notify = None
        class_name = f"SecureHireUsbNotify{id(self)}"
        hinst = kernel32.GetModuleHandleW(None)

        @WNDPROC
        def wndproc(hwnd, msg, wparam, lparam):
            if msg == WM_DEVICECHANGE:
                self._changed.set()  # arrival, removal or DBT_DEVNODES_CHANGED → re-snapshot now
                return 1
            if msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc = wndproc  # keep a reference so the callback is not garbage-collected
        wc = WNDCLASSW()
        wc.lpfnWndProc = wndproc
        wc.hInstance = hinst
        wc.lpszClassName = class_name
        try:
            if not user32.RegisterClassW(ctypes.byref(wc)):
                raise ctypes.WinError(ctypes.get_last_error())
            hwnd = user32.CreateWindowExW(0, class_name, "SecureHire USB notifications", 0, 0, 0, 0, 0, HWND_MESSAGE, None, hinst, None)
            if not hwnd:
                raise ctypes.WinError(ctypes.get_last_error())
            self._hwnd = hwnd
            flt = DEV_BROADCAST_DEVICEINTERFACE_W()
            flt.dbcc_size = ctypes.sizeof(DEV_BROADCAST_DEVICEINTERFACE_W)
            flt.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE
            flt.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE
            notify = user32.RegisterDeviceNotificationW(hwnd, ctypes.byref(flt), DEVICE_NOTIFY_WINDOW_HANDLE)
            if not notify:
                log.warning("RegisterDeviceNotificationW failed (%s); falling back to periodic reconcile only", ctypes.get_last_error())
        except OSError as e:
            log.warning("USB notification window unavailable (%s); using periodic reconcile only", e)
            self._ready.set()
            return
        self._ready.set()
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        if notify:
            user32.UnregisterDeviceNotification(notify)
        user32.UnregisterClassW(class_name, hinst)

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._changed.set()  # wake any waiter
        if self._hwnd:
            user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)
        self._thread.join(3.0)
