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
    u32 is_read;
    u32 inode_id;
    char fname[DNAME_INLINE_LEN];
    u32 count;
};

BPF_PERF_OUTPUT(events);

static int do_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, int is_read){
    struct data_t data = {

    };
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid();
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.is_read = is_read;
    data.count = count;
    data.inode_id = 0;

    u32 file_inodes[INODES_NUMBER] = FILE_INODES;

    struct dentry *d_entry = file->f_path.dentry;
    struct inode *d_inode = d_entry->d_inode;
    struct qstr d_name = d_entry->d_name;
    bpf_probe_read(&data.fname, sizeof(data.fname), d_name.name);
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

int trace_read_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    return do_entry(ctx, file, buf, count, 1);
}
int trace_write_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    return do_entry(ctx, file, buf, count, 0);
}
"""


bpf_text = bpf_text.replace("FILE_INODES", inodes)
bpf_text = bpf_text.replace(
    "INODES_NUMBER", '{}'.format(len(inodes.split(','))))

b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")

# header
print("%-18s %-16s %-6s %-6s %s" % ("TIME(s)", "COMM", "PID", "PPID", "MESSAGE"))


start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    if event.is_read == 1:
        print("%-18.9f %-16s %-6d %-6d %s %d %s %d" % (time_s, event.comm, event.pid, event.ppid, "READ", event.inode_id, event.fname, event.count))
    else:
        print("%-18.9f %-16s %-6d %-6d %s %d %s %d" % (time_s, event.comm, event.pid, event.ppid, "WRITE", event.inode_id, event.fname, event.count))


# print(bpf_text)

b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()