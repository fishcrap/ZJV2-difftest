#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <malloc.h>

#include "qemu.h"

/* only for debug, print the packets */
#if 0
#define CAT(a, b) CAT_IMPL(a, b)
#define CAT_IMPL(a, b) a##b

#define gdb_send(conn, buf, size)       \
  ({                                    \
    printf("send:'%s'\n", (char *)buf); \
    gdb_send(conn, buf, size);          \
  })

#define gdb_recv(conn, size)                               \
  ({                                                       \
    char *CAT(s, __LINE__) = (void *)gdb_recv(conn, size); \
    printf("recv:'%s'\n", (char *)CAT(s, __LINE__));       \
    (uint8_t *)CAT(s, __LINE__);                           \
  })
#endif


const char* init_cmds[] = {
    "qXfer:features:read:target.xml:0,ffb",             // target.xml
    // "qXfer:features:read:riscv-64bit-cpu.xml:0,ffb",    // riscv-64bit-cpu.xml
    "qXfer:features:read:riscv-64bit-fpu.xml:0,ffb",    // riscv-64bit-fpu.xml
    "qXfer:features:read:riscv-64bit-fpu.xml:7fd,ffb",
    // "qXfer:features:read:riscv-64bit-virtual.xml:0,ffb",// riscv-64bit-virtual.xml
    "qXfer:features:read:riscv-csr.xml:0,ffb",          // riscv-csr.xml
    "qXfer:features:read:riscv-csr.xml:7fd,ffb",        
    "qXfer:features:read:riscv-csr.xml:ffa,ffb",      
    "qXfer:features:read:riscv-csr.xml:17f7,ffb",
    // "qRcmd,help,breakpoints"
    // "qRcmd,set:riscv:use-compressed-breakpoints:on"
};

const int csr_num_list[csrs_count] = {
        0x346,  // mstatus
        0x348,  // medeleg
        0x349,  // mideleg
        0x34a,  // mie
        0x38a,  // mip
        0x34b,  // mtvec
        0x386,  // mscratch
        0x387,  // mepc
        0x388,  // mcause
        0x389,  // mtval

        0x146,  // sstatus
        0x14a,  // sie
        0x14b,  // stvec
        0x186,  // scratch
        0x187,  // sepc
        0x188,  // scause
        0x189,  // stval
        0x18a,  // sip 
    };
// reg name=sstatus, regnum=0x146
// reg name=sie, regnum=0x14a
// reg name=stvec, regnum=0x14b
// reg name=scounteren, regnum=0x14c
// reg name=sscratch, regnum=0x186
// reg name=sepc, regnum=0x187
// reg name=scause, regnum=0x188
// reg name=stval, regnum=0x189
// reg name=sip, regnum=0x18a
// reg name=satp, regnum=0x1c6
// reg name=mstatus, regnum=0x346
// reg name=misa, regnum=0x347
// reg name=medeleg, regnum=0x348
// reg name=mideleg, regnum=0x349
// reg name=mie, regnum=0x34a
// reg name=mtvec, regnum=0x34b
// reg name=mcounteren, regnum=0x34c
// reg name=mhpmevent3, regnum=0x369
// reg name=mhpmevent4, regnum=0x36a
// reg name=mhpmevent5, regnum=0x36b
// reg name=mhpmevent6, regnum=0x36c
// reg name=mhpmevent7, regnum=0x36d
// reg name=mhpmevent8, regnum=0x36e
// reg name=mhpmevent9, regnum=0x36f
// reg name=mhpmevent10, regnum=0x370
// reg name=mhpmevent11, regnum=0x371
// reg name=mhpmevent12, regnum=0x372
// reg name=mhpmevent13, regnum=0x373
// reg name=mhpmevent14, regnum=0x374
// reg name=mhpmevent15, regnum=0x375
// reg name=mhpmevent16, regnum=0x376
// reg name=mhpmevent17, regnum=0x377
// reg name=mhpmevent18, regnum=0x378
// reg name=mhpmevent19, regnum=0x379
// reg name=mhpmevent20, regnum=0x37a
// reg name=mhpmevent21, regnum=0x37b
// reg name=mhpmevent22, regnum=0x37c
// reg name=mhpmevent23, regnum=0x37d
// reg name=mhpmevent24, regnum=0x37e
// reg name=mhpmevent25, regnum=0x37f
// reg name=mhpmevent26, regnum=0x380
// reg name=mhpmevent27, regnum=0x381
// reg name=mhpmevent28, regnum=0x382
// reg name=mhpmevent29, regnum=0x383
// reg name=mhpmevent30, regnum=0x384
// reg name=mhpmevent31, regnum=0x385
// reg name=mscratch, regnum=0x386
// reg name=mepc, regnum=0x387
// reg name=mcause, regnum=0x388
// reg name=mtval, regnum=0x389
// reg name=mip, regnum=0x38a
// reg name=pmpcfg0, regnum=0x3e6
// reg name=pmpcfg1, regnum=0x3e7
// reg name=pmpcfg2, regnum=0x3e8
// reg name=pmpcfg3, regnum=0x3e9
// reg name=pmpaddr0, regnum=0x3f6
// reg name=pmpaddr1, regnum=0x3f7
// reg name=pmpaddr2, regnum=0x3f8
// reg name=pmpaddr3, regnum=0x3f9
// reg name=pmpaddr4, regnum=0x3fa
// reg name=pmpaddr5, regnum=0x3fb
// reg name=pmpaddr6, regnum=0x3fc
// reg name=pmpaddr7, regnum=0x3fd
// reg name=pmpaddr8, regnum=0x3fe
// reg name=pmpaddr9, regnum=0x3ff
// reg name=pmpaddr10, regnum=0x400
// reg name=pmpaddr11, regnum=0x401
// reg name=pmpaddr12, regnum=0x402
// reg name=pmpaddr13, regnum=0x403
// reg name=pmpaddr14, regnum=0x404
// reg name=pmpaddr15, regnum=0x405
// reg name=mcycle, regnum=0xb46
// reg name=minstret, regnum=0xb48
// reg name=mhpmcounter3, regnum=0xb49
// reg name=mhpmcounter4, regnum=0xb4a
// reg name=mhpmcounter5, regnum=0xb4b
// reg name=mhpmcounter6, regnum=0xb4c
// reg name=mhpmcounter7, regnum=0xb4d
// reg name=mhpmcounter8, regnum=0xb4e
// reg name=mhpmcounter9, regnum=0xb4f
// reg name=mhpmcounter10, regnum=0xb50
// reg name=mhpmcounter11, regnum=0xb51
// reg name=mhpmcounter12, regnum=0xb52
// reg name=mhpmcounter13, regnum=0xb53
// reg name=mhpmcounter14, regnum=0xb54
// reg name=mhpmcounter15, regnum=0xb55
// reg name=mhpmcounter16, regnum=0xb56
// reg name=mhpmcounter17, regnum=0xb57
// reg name=mhpmcounter18, regnum=0xb58
// reg name=mhpmcounter19, regnum=0xb59
// reg name=mhpmcounter20, regnum=0xb5a
// reg name=mhpmcounter21, regnum=0xb5b
// reg name=mhpmcounter22, regnum=0xb5c
// reg name=mhpmcounter23, regnum=0xb5d
// reg name=mhpmcounter24, regnum=0xb5e
// reg name=mhpmcounter25, regnum=0xb5f
// reg name=mhpmcounter26, regnum=0xb60
// reg name=mhpmcounter27, regnum=0xb61
// reg name=mhpmcounter28, regnum=0xb62
// reg name=mhpmcounter29, regnum=0xb63
// reg name=mhpmcounter30, regnum=0xb64
// reg name=mhpmcounter31, regnum=0xb65
// reg name=cycle, regnum=0xc46
// reg name=time, regnum=0xc47
// reg name=instret, regnum=0xc48
// reg name=hpmcounter3, regnum=0xc49
// reg name=hpmcounter4, regnum=0xc4a
// reg name=hpmcounter5, regnum=0xc4b
// reg name=hpmcounter6, regnum=0xc4c
// reg name=hpmcounter7, regnum=0xc4d
// reg name=hpmcounter8, regnum=0xc4e
// reg name=hpmcounter9, regnum=0xc4f
// reg name=hpmcounter10, regnum=0xc50
// reg name=hpmcounter11, regnum=0xc51
// reg name=hpmcounter12, regnum=0xc52
// reg name=hpmcounter13, regnum=0xc53
// reg name=hpmcounter14, regnum=0xc54
// reg name=hpmcounter15, regnum=0xc55
// reg name=hpmcounter16, regnum=0xc56
// reg name=hpmcounter17, regnum=0xc57
// reg name=hpmcounter18, regnum=0xc58
// reg name=hpmcounter19, regnum=0xc59
// reg name=hpmcounter20, regnum=0xc5a
// reg name=hpmcounter21, regnum=0xc5b
// reg name=hpmcounter22, regnum=0xc5c
// reg name=hpmcounter23, regnum=0xc5d
// reg name=hpmcounter24, regnum=0xc5e
// reg name=hpmcounter25, regnum=0xc5f
// reg name=hpmcounter26, regnum=0xc60
// reg name=hpmcounter27, regnum=0xc61
// reg name=hpmcounter28, regnum=0xc62
// reg name=hpmcounter29, regnum=0xc63
// reg name=hpmcounter30, regnum=0xc64
// reg name=hpmcounter31, regnum=0xc65
// reg name=mvendorid, regnum=0xf57
// reg name=marchid, regnum=0xf58
// reg name=mimpid, regnum=0xf59
// reg name=mhartid, regnum=0xf5a

int qemu_start(const char *elf, int port) {
    // char remote_s[100];
    const char *exec = "qemu-system-riscv64";
    // snprintf(remote_s, sizeof(remote_s), "tcp::%d", port);

    // execlp(exec, exec, "-S", "-gdb", remote_s, "-bios", elf, "-M", "virt", "-m", "64M", "-nographic", NULL);
    execlp(exec, exec, "-S", "-s", "-bios", elf, "-M", "virt", "-m", "64M", "-nographic", NULL);

    return -1;
}

qemu_conn_t *qemu_connect(int port) {
    qemu_conn_t *conn = NULL;
    while (
            (conn = gdb_begin_inet("127.0.0.1", port)) == NULL) {
        usleep(1);
    }

    return conn;
}

// bool qemu_memcpy_to_qemu_small(qemu_conn_t *conn, uint32_t dest, void *src, int len) {
//     char *buf = (char *) malloc(len * 2 + 128);
//     assert(buf != NULL);
//     int p = sprintf(buf, "M0x%x,%x:", dest, len);
//     int i;
//     for (i = 0; i < len; i++) {
//         p += sprintf(buf + p, "%c%c",
//                      hex_encode(((uint8_t *) src)[i] >> 4),
//                      hex_encode(((uint8_t *) src)[i] & 0xf));
//     }

//     gdb_send(conn, (const uint8_t *) buf, strlen(buf));
//     free(buf);

//     size_t size;
//     uint8_t *reply = gdb_recv(conn, &size);
//     bool ok = !strcmp((const char *) reply, "OK");
//     free(reply);

//     return ok;
// }

// bool qemu_memcpy_to_qemu(qemu_conn_t *conn, uint32_t dest, void *src, int len) {
//     const int mtu = 1500;
//     bool ok = true;
//     while (len > mtu) {
//         ok &= qemu_memcpy_to_qemu_small(conn, dest, src, mtu);
//         dest += mtu;
//         src += mtu;
//         len -= mtu;
//     }
//     ok &= qemu_memcpy_to_qemu_small(conn, dest, src, len);
//     return ok;
// }

void qemu_getregs(qemu_conn_t *conn, qemu_regs_t *r) {
    // read GPRs
    gdb_send(conn, (const uint8_t *) "g", 1);
    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);

    // printf("[DEBUG] check reply\n%s\n", reply);

    uint8_t *p = reply;
    uint8_t c;
    for (int i = 0; i < 33; i++) {
        c = p[16];
        p[16] = '\0';
        r->array[i] = gdb_decode_hex_str(p);
        p[16] = c;
        p += 16;
    }

    free(reply);
    qemu_getfprs(conn, r);
    qemu_getcsrs(conn, r);
}

bool qemu_setregs(qemu_conn_t *conn, qemu_regs_t *r) {
    int len = sizeof(qemu_regs_t);
    char *buf = (char *) malloc(len * 2 + 128);
    assert(buf != NULL);
    buf[0] = 'G';

    void *src = r;
    int p = 1;
    for (int i = 0; i < len; i++) {
        p += sprintf(buf + p, "%c%c",
                     hex_encode(((uint8_t *) src)[i] >> 4),
                     hex_encode(((uint8_t *) src)[i] & 0xf));
    }

    gdb_send(conn, (const uint8_t *) buf, strlen(buf));
    free(buf);

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    bool ok = !strcmp((const char *) reply, "OK");
    free(reply);

    return ok;
}

bool qemu_single_step(qemu_conn_t *conn) {
    char buf[] = "vCont;s:1";
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));
    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    free(reply);
    return true;
}

void qemu_break(qemu_conn_t *conn, uint64_t entry) {
    char buf[32];
    snprintf(buf, sizeof(buf), "Z0,%016lx,4", entry);
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    free(reply);
}

void qemu_remove_breakpoint(qemu_conn_t *conn, uint64_t entry) {
    char buf[32];
    snprintf(buf, sizeof(buf), "z0,%016lx,4", entry);
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    free(reply);
}

void qemu_continue(qemu_conn_t *conn) {
    char buf[] = "vCont;c:1";
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));
    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    free(reply);
}

void qemu_disconnect(qemu_conn_t *conn) {
    gdb_end(conn);
}

inst_t qemu_getinst(qemu_conn_t *conn, uint32_t pc) {
    char buf[32];
    snprintf(buf, sizeof(buf), "m0x%x,4", pc);
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);

    reply[8] = '\0';
    inst_t inst = gdb_decode_inst(reply);

    free(reply);
    return inst;
}

bool qemu_setinst(qemu_conn_t *conn, uint32_t pc, inst_t *inst) {
    int len = sizeof(inst_t);
    char buf[2*4+128];

    int p = snprintf(buf, sizeof(buf), "M%x,4:", pc); // 1+8+1+1+1 = 12

    void *src = inst;
    int i;
    for (i = 0; i < len; i++) {
        p += sprintf(buf + p, "%c%c",
                     hex_encode(((uint8_t *) src)[i] >> 4),
                     hex_encode(((uint8_t *) src)[i] & 0xf));
    }
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    bool ok = !strcmp((const char *) reply, "OK");
    free(reply);

    return ok;
}

uint64_t qemu_getmem(qemu_conn_t *conn, uint32_t addr) {
    char buf[32];
    snprintf(buf, sizeof(buf), "m0x%x,4", addr);
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);

    reply[8] = '\0';
    uint64_t content = gdb_decode_hex_str(reply);
    printf("0x%x: %08lx\n", addr, content);

    free(reply);
    return content;
}

uint64_t qemu_read_mem(qemu_conn_t *conn, uint32_t addr, int nbyte) {
    assert(nbyte <= 8);
    int buf_size = 2 * nbyte + 20;
    char *buf = (char *) malloc(buf_size);
    snprintf(buf, buf_size, "m0x%x,%x", addr, nbyte);
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    
    reply[size] = '\0';
    uint64_t content = gdb_decode_hex_str(reply);
    // printf("0x%x: %016lx\n", addr, content);

    free(reply);
    return content;
}

// can't work properly
bool qemu_setcsrs(qemu_conn_t *conn, int csr_num, uint64_t *data) {
    int len = sizeof(uint64_t);
    char buf[2*4+128];

    int p = snprintf(buf, sizeof(buf), "P%x=", csr_num); // 1+8+1+1+1 = 12
    printf("%s\n", buf);

    void *src = data;
    int i;
    for (i = 0; i < len; i++) {
        p += sprintf(buf + p, "%c%c",
                     hex_encode(((uint8_t *) src)[i] >> 4),
                     hex_encode(((uint8_t *) src)[i] & 0xf));
    }
    printf("%s\n", buf);

    gdb_send(conn, (const uint8_t *) buf, strlen(buf));
    // free(buf);

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    bool ok = !strcmp((const char *) reply, "OK");
    printf("%s\n", (const char *) reply);
    assert(ok == true);
    free(reply);

    return ok;
}

bool qemu_set_csr(qemu_conn_t *conn, int csr_num, uint64_t *data) {
    int len = sizeof(uint64_t);
    char buf[2*4+128];

    int p = snprintf(buf, sizeof(buf), "P%x=", csr_num_list[csr_num]); // 1+8+1+1+1 = 12
    // printf("%s\n", buf);

    void *src = data;
    int i;
    for (i = 0; i < len; i++) {
        p += sprintf(buf + p, "%c%c",
                     hex_encode(((uint8_t *) src)[i] >> 4),
                     hex_encode(((uint8_t *) src)[i] & 0xf));
    }
    // printf("%s\n", buf);

    gdb_send(conn, (const uint8_t *) buf, strlen(buf));
    // free(buf);

    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);
    bool ok = !strcmp((const char *) reply, "OK");
    // printf("%s\n", (const char *) reply);
    assert(ok == true);
    free(reply);

    return ok;
}

void qemu_getcsrs(qemu_conn_t *conn, qemu_regs_t *r) {
    for (int i = 0; i < csrs_count; i++) {
        qemu_get_csr(conn, i, &r->array[65 + i]);
        // char buf[32];
        // snprintf(buf, sizeof(buf), "p%x", csr_num_list[i]);
        // gdb_send(conn, (const uint8_t *) buf, strlen(buf));
        // size_t size;
        // uint8_t *reply = gdb_recv(conn, &size);

        // r->array[65 + i] = gdb_decode_hex_str(reply);
        // free(reply);
    }   
}

void qemu_get_csr(qemu_conn_t *conn, int csr_num, uint64_t *csr_data) {
    char buf[32];
    snprintf(buf, sizeof(buf), "p%x", csr_num_list[csr_num]);
    gdb_send(conn, (const uint8_t *) buf, strlen(buf));
    size_t size;
    uint8_t *reply = gdb_recv(conn, &size);

    *csr_data = gdb_decode_hex_str(reply);
    free(reply);
}

void qemu_getfprs(qemu_conn_t *conn, qemu_regs_t *r) {
    const int fpu_base = 33;

    for (int i = 0; i < 32; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "p%x", (fpu_base + i));
        gdb_send(conn, (const uint8_t *) buf, strlen(buf));
        size_t size;
        uint8_t *reply = gdb_recv(conn, &size);

        r->array[33 + i] = gdb_decode_hex_str(reply);
        // if (i == 1) {
        //     printf("[DEBUG] ft1 = %lx\n", r->array[33 + i]);
        // }
        free(reply);
    }   
}

void qemu_init(qemu_conn_t *conn) {
    int init_cmds_count = sizeof(init_cmds) / sizeof(init_cmds[0]);
    
    for (int i =0; i < init_cmds_count; i++) {
        gdb_send(conn, (const uint8_t *) init_cmds[i], strlen(init_cmds[i]));
        size_t size;
        uint8_t *reply = gdb_recv(conn, &size);
        if (i == 7) {
            reply[size] = '\0';
            printf("%s\n", (const char *) gdb_decode_hex_str(reply));
        }
        free(reply);
    }
}

void qemu_disable_int(qemu_conn_t *conn) {
    const int mie_num = 3;
    const uint64_t disable_mie_mtip = ~(1 << 7);
    uint64_t *mie_data = (uint64_t *)malloc(sizeof(uint64_t));
    qemu_get_csr(conn, mie_num, mie_data);
    *mie_data &= disable_mie_mtip;
    qemu_set_csr(conn, mie_num, mie_data);
    free(mie_data);
}

void qemu_enable_int(qemu_conn_t *conn) {
    const int mie_num = 3;
    const uint64_t enable_mie_mtip = 1 << 7;
    uint64_t *mie_data = (uint64_t *)malloc(sizeof(uint64_t));
    qemu_get_csr(conn, mie_num, mie_data);
    *mie_data |= enable_mie_mtip;
    qemu_set_csr(conn, mie_num, mie_data);
    free(mie_data);
}

void qemu_zero_csr_wpri(qemu_conn_t *conn) {
    const int mstatus_num = 0;
    const int mideleg_num = 2;
    const uint64_t mstatus_wpri_mask = 0x8000003f007fffea;
    const uint64_t mideleg_wpri_mask = 0x0BBB;
    uint64_t *csr_data = (uint64_t *)malloc(sizeof(uint64_t));
    
    qemu_get_csr(conn, mstatus_num, csr_data);
    *csr_data &= mstatus_wpri_mask;
    qemu_set_csr(conn, mstatus_num, csr_data);

    qemu_get_csr(conn, mideleg_num, csr_data);
    *csr_data &= mideleg_wpri_mask;
    qemu_set_csr(conn, mideleg_num, csr_data);
    free(csr_data);
}