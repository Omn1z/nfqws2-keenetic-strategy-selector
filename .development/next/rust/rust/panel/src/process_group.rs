/// Own the descendant processes of a command run with `process_group(0)`.
/// Router utilities can leave children holding pipes or executing postinstall
/// scripts after their immediate parent exits.
pub(crate) struct ProcessGroup(pub Option<u32>);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // pid came from the child that leads this private process group.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
}
