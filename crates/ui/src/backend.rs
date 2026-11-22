//! Starts the per-user background service for this GUI, so the user only opens one program.
//!
//! The child is the sibling `lineguard-service.exe --console`: it runs as the same user and
//! logon session (which the pipe authentication requires), has no window, and never installs
//! or removes WFP rules. It lives in a kill-on-close Job owned by the GUI, so it ends with it.
use std::{
    io,
    os::windows::{io::AsRawHandle, process::CommandExt},
    process::{Child, Command, Stdio},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    },
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct Backend {
    job: HANDLE,
    child: Child,
}
impl Backend {
    pub fn start() -> io::Result<Self> {
        let exe = std::env::current_exe()?.with_file_name("lineguard-service.exe");
        if !exe.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "同目录缺少 lineguard-service.exe；请把下载包里的 4 个程序放在同一文件夹",
            ));
        }
        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let guard = JobGuard(job);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut child = Command::new(&exe)
            .arg("--console")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()?;
        if unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) } == 0 {
            let error = io::Error::last_os_error();
            let _ = child.kill();
            return Err(error);
        }
        std::mem::forget(guard);
        Ok(Self { job, child })
    }
    /// Some(code) once the service has exited (for example because another one already runs).
    pub fn exited(&mut self) -> Option<i32> {
        self.child
            .try_wait()
            .ok()
            .flatten()
            .map(|s| s.code().unwrap_or(-1))
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        // Closing the last Job handle terminates the service we started; nothing else.
        unsafe {
            CloseHandle(self.job);
        }
    }
}
struct JobGuard(HANDLE);
impl Drop for JobGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
