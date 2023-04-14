import os, sys, stat

def get_inode_number(files):
    inode_dict = {}
    inodes = '{'
    total_files = 0
    for file in files.split(','):
        total_files = total_files + 1
        if total_files > 15:
            print("Max file limit reached")
            break
        inode_id = os.lstat(file)[stat.ST_INO]
        if inode_id not in inode_dict:
            inode_dict[inode_id] = file
            inodes = "{},{}".format(inodes,inode_id)
    inodes += "}"
    return inodes.replace('{,', '{'), inode_dict


inodes, inode_dict = get_inode_number('/home/vamshi/Desktop/mtp/filetrack/dirtotrack/cat.txt,/home/vamshi/Desktop/mtp/filetrack/dirtotrack/bat.txt')
print(inodes)
print(inode_dict)


from bcc import BPF
from bcc.utils import printb

bpf_text = """
# include <uapi/linux/ptrace.h>
# include <linux/blkdev.h>
# include <linux/sched.h>

struct data_t{
    u32 pid;
    u32 ppid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u32 inode_id;
    u32 inode_id_parent_old;
    u32 inode_id_parent_new;

    u32 is_delete;
    char fname[DNAME_INLINE_LEN];
    char fname2[DNAME_INLINE_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_unlink(struct pt_regs *ctx, struct user_namespace *ns, struct inode *dir, struct dentry *dentry){
    u32 file_inodes[INODES_NUMBER] = FILE_INODES;
    struct data_t data = {

    };
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid();
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.is_delete = 1;
    data.inode_id = 0;
    struct qstr d_name = dentry->d_name;
    bpf_probe_read(&data.fname, sizeof(data.fname), d_name.name);


    struct inode *d_inode = dentry->d_inode;
    u32 curr_inode = d_inode->i_ino;
    for (int i = 0; i < INODES_NUMBER; i++){
        if (file_inodes[i] == curr_inode){
            data.inode_id = curr_inode;
            break;
        }
    }

    if (data.inode_id == 0)
        return 0;
    events.perf_submit(ctx,&data,sizeof(data));
    return 0;
}

int trace_rename(struct pt_regs *ctx, struct renamedata *rd){
    u32 file_inodes[INODES_NUMBER] = FILE_INODES;
    struct dentry *old_dentry = rd->old_dentry;
    struct dentry *new_dentry = rd->new_dentry;
    struct qstr s_name = old_dentry->d_name;
    struct qstr d_name = new_dentry->d_name;
    if (s_name.len == 0 || d_name.len == 0)
        return 0;

    
    struct data_t data = {

    };
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid();
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.is_delete = 0;
    data.inode_id = 0;
    bpf_probe_read(&data.fname, sizeof(data.fname), s_name.name);
    bpf_probe_read(&data.fname2, sizeof(data.fname), d_name.name);

    struct dentry *old_parent = old_dentry->d_parent;
    struct inode *d_inode_old = old_parent->d_inode;
    data.inode_id_parent_old = d_inode_old->i_ino;

    struct dentry *new_parent = new_dentry->d_parent;
    struct inode *d_inode_new = new_parent->d_inode;
    data.inode_id_parent_new = d_inode_new->i_ino;

    struct inode *d_inode = old_dentry->d_inode;
    u32 curr_inode = d_inode->i_ino;
    for (int i = 0; i < INODES_NUMBER; i++){
        if (file_inodes[i] == curr_inode){
            data.inode_id = curr_inode;
            break;
        }
    }

    if (data.inode_id == 0)
        return 0;
    events.perf_submit(ctx,&data,sizeof(data));
    return 0;
}
"""


bpf_text = bpf_text.replace("FILE_INODES", inodes)
bpf_text = bpf_text.replace(
    "INODES_NUMBER", '{}'.format(len(inodes.split(','))))

b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_unlink", fn_name="trace_unlink")
b.attach_kprobe(event="vfs_rmdir", fn_name="trace_unlink")
b.attach_kprobe(event="vfs_rename", fn_name="trace_rename")

# header
print("%-18s %-16s %-6s %-6s %s" % ("TIME(s)", "COMM", "PID", "PPID", "MESSAGE"))


start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    if event.is_delete == 0:
        print("%-18.9f %-16s %-6d %-6d %s %d %s %s %s %d %d" % (time_s, event.comm, event.pid, event.ppid, "RENAME", event.inode_id, event.fname, " > ", event.fname2, event.inode_id_parent_old, event.inode_id_parent_new))
    else:
        print("%-18.9f %-16s %-6d %-6d %s %d %s" % (time_s, event.comm, event.pid, event.ppid, "DELETE", event.inode_id, event.fname))


# print(bpf_text)

b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()