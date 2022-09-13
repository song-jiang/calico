c:\temp\bpftool.exe prog load c:\k\xdp.o /sys/fs/bpf/song-xdp
c:\temp\bpftool.exe prog show

c:\temp\bpftool.exe net attach xdp id 983041 dev 'ethernet_32773'

# c:\temp\bpftool.exe net detach xdp dev 'ethernet_32773'


C:\temp\bpftool.exe prog load C:\k\tail_call_multiple.o /sys/fs/bpf/song-tail-call
