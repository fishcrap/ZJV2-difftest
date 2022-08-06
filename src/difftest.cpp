#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <time.h>

#include "verilated_vcd_c.h"

#include "qemu.h"
#include "dut.h"
#include "isa.h"
#include "ram.h"
#include "queue.h"

int total_instructions;

// #define WAVE_TRACE
// #define IPC_TRACE
// #define NO_DIFF
// #define RUN_QEMU_ONLY
#define SYNC_MMIO
// #define FW_OPENSBI
#define SYNC_TIME_INT
// #define USE_BR_POINT
#define MIE_MTIE (1 << 7)
#define MIP_MTIP (1 << 7)

uint64_t dump_start = 18830000;
// static uint64_t total_time = 0;
static VerilatedContext* contextp;

// dump qemu registers
void print_qemu_registers(qemu_regs_t *regs, bool wpc) {
    if (wpc) eprintf("$pc:  0x%016lx\n", regs->pc);
    eprintf("$zero:0x%016lx  $ra:0x%016lx  $sp: 0x%016lx  $gp: 0x%016lx\n",
            regs->gpr[0], regs->gpr[1], regs->gpr[2], regs->gpr[3]);
    eprintf("$tp:  0x%016lx  $t0:0x%016lx  $t1: 0x%016lx  $t2: 0x%016lx\n",
            regs->gpr[4], regs->gpr[5], regs->gpr[6], regs->gpr[7]);
    eprintf("$fp:  0x%016lx  $s1:0x%016lx  $a0: 0x%016lx  $a1: 0x%016lx\n",
            regs->gpr[8], regs->gpr[9], regs->gpr[10], regs->gpr[11]);
    eprintf("$a2:  0x%016lx  $a3:0x%016lx  $a4: 0x%016lx  $a5: 0x%016lx\n",
            regs->gpr[12], regs->gpr[13], regs->gpr[14], regs->gpr[15]);
    eprintf("$a6:  0x%016lx  $a7:0x%016lx  $s2: 0x%016lx  $s3: 0x%016lx\n",
            regs->gpr[16], regs->gpr[17], regs->gpr[18], regs->gpr[19]);
    eprintf("$s4:  0x%016lx  $s5:0x%016lx  $s6: 0x%016lx  $s7: 0x%016lx\n",
            regs->gpr[20], regs->gpr[21], regs->gpr[22], regs->gpr[23]);
    eprintf("$s8:  0x%016lx  $s9:0x%016lx  $s10:0x%016lx  $s11:0x%016lx\n",
            regs->gpr[24], regs->gpr[25], regs->gpr[26], regs->gpr[27]);
    eprintf("$t3:  0x%016lx  $t4:0x%016lx  $t5: 0x%016lx  $t6: 0x%016lx\n",
            regs->gpr[28], regs->gpr[29], regs->gpr[30], regs->gpr[31]);
    eprintf("$ft0:  0x%016lx  $ft1:0x%016lx  $ft2: 0x%016lx  $ft3: 0x%016lx\n",
        regs->fpr[33], regs->fpr[34], regs->fpr[35], regs->fpr[36]);
    eprintf("$ft4:  0x%016lx  $ft5:0x%016lx  $ft6: 0x%016lx  $ft7: 0x%016lx\n",
        regs->fpr[37], regs->fpr[38], regs->fpr[39], regs->fpr[40]);
    eprintf("$fs0:  0x%016lx  $fs1:0x%016lx  $fa0: 0x%016lx  $fa1: 0x%016lx\n",
        regs->fpr[41], regs->fpr[42], regs->fpr[43], regs->fpr[44]);
    eprintf("$fa2:  0x%016lx  $fa3:0x%016lx  $fa4: 0x%016lx  $fa5: 0x%016lx\n",
        regs->fpr[45], regs->fpr[46], regs->fpr[47], regs->fpr[48]);
    eprintf("$fa6:  0x%016lx  $fa7:0x%016lx  $fs2: 0x%016lx  $fs3: 0x%016lx\n",
        regs->fpr[49], regs->fpr[50], regs->fpr[51], regs->fpr[52]);
    eprintf("$fs4:  0x%016lx  $fs5:0x%016lx  $fs6: 0x%016lx  $fs7: 0x%016lx\n",
        regs->fpr[53], regs->fpr[54], regs->fpr[55], regs->fpr[56]);
    eprintf("$fs8:  0x%016lx  $fs9:0x%016lx  $fs10: 0x%016lx  $fs11: 0x%016lx\n",
        regs->fpr[57], regs->fpr[58], regs->fpr[59], regs->fpr[60]);
    eprintf("$ft8:  0x%016lx  $ft9:0x%016lx  $ft10: 0x%016lx  $ft11: 0x%016lx\n",
        regs->fpr[61], regs->fpr[62], regs->fpr[63], regs->fpr[64]);
    eprintf("$mstatus: 0x%016lx  $medeleg: 0x%016lx  $mideleg: 0x%016lx\n",
            regs->array[65], regs->array[66], regs->array[67]);
    eprintf("$mie:     0x%016lx  $mip:     0x%016lx  $mtvec:   0x%016lx  $mscratch: 0x%016lx\n",
            regs->array[68], regs->array[69], regs->array[70], regs->array[71]);
    eprintf("$mepc:    0x%016lx  $mcause:  0x%016lx  $mtval:   0x%016lx\n",
            regs->array[72], regs->array[73], regs->array[74]);
    eprintf("$sstatus: 0x%016lx  $sie:     0x%016lx  $stvec:   0x%016lx  $sscratch: 0x%016lx\n",
            regs->array[75], regs->array[76], regs->array[77], regs->array[78]);
    eprintf("$sepc:    0x%016lx  $scause:  0x%016lx  $stval:   0x%016lx  $sip:      0x%016lx\n",
            regs->array[79], regs->array[80], regs->array[81], regs->array[82]);
}


void difftest_start_qemu(const char *path, int port, int ppid) {
    // install a parent death signal in the child
    int r = prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (r == -1) { panic("prctl error"); }

    if (getppid() != ppid) { panic("parent has died"); }

    close(0); // close STDIN

    qemu_start(path, port);    // start qemu in single-step mode and stub gdb
}


// void __attribute__((noinline))
// difftest_finish_qemu(qemu_conn_t *conn) {
//     for (int i = 0; i < 2; i++) {
//         qemu_regs_t regs = {0};
//         qemu_single_step(conn);
//         qemu_getregs(conn, &regs, &csrs);
//         print_qemu_registers(&regs, true);
//     }
//     abort();
// }


// 比较寄存器，包括 GPRs 和 CSRs
const int pc_size = 10;
static uint64_t last_3_qpcs[pc_size] = {0};
// static FixedQueue last_dut_pcs(10);
bool difftest_regs (qemu_regs_t *regs, qemu_regs_t *dut_regs, diff_pcs *dut_pcs) {
    const char *alias[regs_count] = {
        "zero", "ra", "sp", "gp",
        "tp", "t0", "t1", "t2",
        "fp", "s1", "a0", "a1",
        "a2", "a3", "a4", "a5",
        "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7",
        "s8", "s9", "s10", "s11",
        "t3", "t4", "t5", "t6", "pc",
        "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
        "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5",
        "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
        "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
        "mstatus", "medeleg", "mideleg", "mie", 
        "mip", "mtvec", "mscratch", "mepc", 
        "mcause", "mtval", "sstatus", "sie", "stvec", 
        "sscratch", "sepc", "scause", "stval", "sip"
    };

    
    for (int i = 0; i < 32; i++) {
        // GPR
        if (regs->gpr[i] != dut_regs->gpr[i]) {
            sleep(0.5);
            for (int j = 0; j < pc_size; j++) {
                printf("QEMU PC at [0x%016lx]\n", last_3_qpcs[j]);
            }
            printf("\x1B[31mError in $%s, QEMU %lx, ZJV2 %lx\x1B[37m\n", 
                alias[i], regs->gpr[i], dut_regs->gpr[i]);
            return false;
        }
        // FPR
        if (regs->fpr[i + 33] != dut_regs->fpr[i + 33]) {
            sleep(0.5);
            for (int j = 0; j < pc_size; j++) {
                printf("QEMU PC at [0x%016lx]\n", last_3_qpcs[j]);
            }
            printf("\x1B[31mError in $%s, QEMU %lx, ZJV2 %lx\x1B[37m\n", 
                alias[33 + i], regs->fpr[i + 33], dut_regs->fpr[i + 33]);
            return false;
        }
    }

    // CSR
    for (int i = 65; i < regs_count; i++) {
        if (i == 65 || i == 75) { continue; }   // skip `mstatus` and `sstatus`
#ifdef SYNC_TIME_INT
        if (i == 68) { // trust dut's `mie.MTIE`
            regs->array[i] = (regs->array[i] & ~MIE_MTIE) | (dut_regs->array[i] & MIE_MTIE);
        }
        if (i == 69) { // trust dut's `mip.MTIP`
            regs->array[i] = (regs->array[i] & ~MIP_MTIP) | (dut_regs->array[i] & MIP_MTIP);
        }
#endif
        // if (i == 67) {// mideleg
        //     continue;
        // }
        if (regs->array[i] != dut_regs->array[i]) {
            sleep(0.5);
            for (int j = 0; j < pc_size; j++) {
                printf("QEMU PC at [0x%016lx]\n", last_3_qpcs[j]);
            }
            printf("\x1B[31mError in $%s, QEMU %lx, ZJV2 %lx\x1B[37m\n", 
                alias[i], regs->array[i], dut_regs->array[i]);
            return false;
        }
    }

    for (int i = 0; i < pc_size - 1; i++) {
        last_3_qpcs[i] = last_3_qpcs[i + 1];
    }
    last_3_qpcs[pc_size - 1] = regs->pc - 4;
    return true;
}

char *get_wf_filename() {
    char *filename = new char[64];
    time_t now = time(0);
    strftime(filename, sizeof(filename), "%F", localtime(&now));
    strcat(filename, ".vcd"); 
    return filename;
}

bool check_end_ysyx() {
    return dut->io_difftest_finish;
}

bool check_and_close_difftest(qemu_conn_t *conn, VerilatedVcdC* vfp, VerilatedContext* context) {
    if (check_end_ysyx()) {
        printf("difftest pass!\n");

#ifdef IPC_TRACE
        // print information
        printf("Total Instructions: %d\n", total_instructions);
        printf("Total Cycles: %lld\n", dut->io_difftest_counter);
        printf("IPC: %lf\n", double(total_instructions) / dut->io_difftest_counter);
        printf("Both Cache Stall Cycles: %lld\n", dut->io_difftest_common);
        printf("\tDcache Stall Cycles: %lld\n", dut->io_difftest_dstall);
        printf("\tIcache Stall Cycles: %lld\n", dut->io_difftest_istall);
        printf("MDU Stall Cycles: %lld\n", dut->io_difftest_mduStall);
#endif

#ifdef WAVE_TRACE
        dut_step(100, vfp, context);
        vfp->close();
        delete vfp;
        delete context;
#endif
        qemu_disconnect(conn);
        return true;
    }
    return false;
}

// bool check_print_ysyx() {
//     return dut->io_difftest_print;
// }

bool ysyx_skip_print(qemu_conn_t *conn, uint32_t pc) {
    inst_t nop;
    nop.val = 0x13;
    return qemu_setinst(conn, pc, &nop);
}

void print_total_time() {
    printf("\x1B[32mtotal time: %d\x1B[0m\n", contextp->time());
}

bool is_stop = false;
void stop(int signo) {
    printf("receive CTRL C INT!\n");
    is_stop = true;
    for (int j = 0; j < pc_size; j++) {
        printf("QEMU PC at [0x%016lx]\n", last_3_qpcs[j]);
    }
    print_total_time();
}

bool is_abort = false;
void abort(int signo) {
    printf("recieve abort signal!\n");
    is_abort = true;
    for (int j = 0; j < pc_size; j++) {
        printf("QEMU PC at [0x%016lx]\n", last_3_qpcs[j]);
    }
    print_total_time();
}


int difftest_body(const char *path, int port) {
    int result = 0;
    Verilated::traceEverOn(true);
    VerilatedVcdC* vfp;
    
    dut = new VTileForVerilator;
    vfp = new VerilatedVcdC;
    contextp = new VerilatedContext;
#ifdef WAVE_TRACE
    dut->trace(vfp, 99);
    vfp->open("sim.vcd");
#endif
    qemu_regs_t regs = {0};
    qemu_regs_t dut_regs = {0};

    diff_pcs dut_pcs = {0};
    diff_mmios dut_mmios = {0};
    int bubble_count = 0;
    uint64_t time_zero_csr = 30;

    qemu_conn_t *conn = qemu_connect(port);
    qemu_init(conn);                            // 初始化 GDB，发送 qXfer 命令注册 features 


    extern uint64_t elf_entry;
    regs.pc = elf_entry;
#ifdef FW_OPENSBI
    regs.a1 = 0x83000000;
    // regs.a2 = 0x1028;
    // regs.t0 = 0x80000000;
#endif

    qemu_break(conn, elf_entry);
    qemu_continue(conn);
    qemu_remove_breakpoint(conn, elf_entry);
    qemu_setregs(conn, &regs);


    init_ram("testfile.bin", conn);
    // init_ram("../linux-opensbi.bin", conn);
    // assert(false);

    // set up device under test
    dut_reset(10, vfp, contextp);
    dut_sync_reg(0, 0, false);


    // 
    // inst_t nop;
    // nop.val = 0x13;
    // qemu_setinst(conn, 0x800004f8, &nop);
    // // qemu_setinst(conn, 0x8000535c, &nop);
    // // qemu_setinst(conn, 0x80005360, &nop);
    // qemu_setinst(conn, 0x80005394, &nop);

    // inst_t a;
    // a = qemu_getinst(conn, 0x800004f8);
    // printf("0x800004f8: %08x\n", a.val);
    // a = qemu_getinst(conn, 0x8000535c);
    // printf("0x8000535c: %08x\n", a.val);
    // a = qemu_getinst(conn, 0x80005360);
    // printf("0x80005360: %08x\n", a.val);
    // a = qemu_getinst(conn, 0x80005394);
    // printf("0x80005394: %08x\n", a.val);


    signal(SIGINT, stop);
    // signal(SIGABRT, abort);
#ifdef NO_DIFF
    while(1) {
        if (!is_stop) {
            dut_step(1, vfp, contextp);
        }
        else {
            goto END;
        }
    }
#endif

#ifdef RUN_QEMU_ONLY
#if !defined(NO_DIFF)
    qemu_break(conn, 0x802000d8);
    // qemu_continue(conn);
    while(1) {
        if (!is_stop && !is_abort) {
            uint64_t csr_data = 0x0;
            qemu_zero_csr_wpri(conn);
            qemu_set_csr(conn, 2, 0x0);
            qemu_single_step(conn);
            qemu_getregs(conn, &regs);
            for (int i = 0; i < pc_size - 1; i++) {
                last_3_qpcs[i] = last_3_qpcs[i + 1];
            }
            last_3_qpcs[pc_size - 1] = regs.pc;
            
            printf("pc: %016lx\tmideleg:%016lx\n", regs.pc, regs.mideleg);
        }
        else {
            goto END;
        }
    }
#endif
#endif

#ifdef USE_BR_POINT
    uint64_t br_point = 0x802000d8;
    br_point = 0x8000d058;
    bool first_hit = true;
    bool hit_2nd_inst = false;
    qemu_break(conn, br_point);
    qemu_continue(conn);
    qemu_getregs(conn, &regs);
    printf("QEMU break at pc: [%016lx]\n", regs.pc);
#endif


    while (1) {
        if (is_stop || is_abort) break;
        if (contextp->time() == time_zero_csr) { qemu_zero_csr_wpri(conn); }
        dut_step(1, vfp, contextp);
        if (check_and_close_difftest(conn, vfp, contextp))
            return 0;
        bubble_count = 0;

        while (dut_commit() == 0) {
            dut_step(1, vfp, contextp);
            if (check_and_close_difftest(conn, vfp, contextp))
                return 0;

            bubble_count++;
            // printf("dut bubble count: %d\n", bubble_count);

            if (bubble_count > 200) {
                printf("\x1B[31mToo many bubbles!!!!!!\x1B[0m\n");
                break;
            }
        }

        total_instructions += dut_commit();

#ifdef USE_BR_POINT
        dut_getpcs(&dut_pcs);
        if (first_hit && dut_pcs.mycpu_pcs[0] != br_point && dut_pcs.mycpu_pcs[1] != br_point && dut_pcs.mycpu_pcs[2] != br_point) {
            continue;
        } else {
            if (first_hit) {
                sleep(0.25);
                printf("hit DUT pc [%016lx]\n", br_point);
                int idx = -1;
                for (int i = 0; i < 3; i++) {
                    if (dut_pcs.mycpu_pcs[i] == br_point) {
                        idx = i;
                        break;
                    }
                }
                int orders[3] = {dut->io_difftest_orders_0, dut->io_difftest_orders_1, dut->io_difftest_orders_2};
                if (orders[idx] == 1) {
                    hit_2nd_inst = true;
                }
            }
            first_hit = false;
        }
        for (int i = 0; i < dut_commit(); i++) {
            if (hit_2nd_inst) {
                hit_2nd_inst = false;
                continue;
            }
            qemu_single_step(conn);
#ifdef SYNC_TIME_INT
            qemu_disable_int(conn);
#endif
        }



#else
        for (int i = 0; i < dut_commit(); i++) {
            qemu_single_step(conn);
#ifdef SYNC_TIME_INT
            qemu_disable_int(conn);
#endif
            sleep(0.25);

#ifdef TRACE
            qemu_getregs(conn, &regs);
            printf("\nQEMU\n");
            print_qemu_registers(&regs, true);
            printf("\nDUT\n");
            for (int i = 0; i < 3; i++) {
                printf("$pc_%d:0x%016lx  ", i, dut_pcs.mycpu_pcs[i]);
            }
            printf("\n");
            print_qemu_registers(&dut_regs, false);
            printf("==============\n");
#endif
        }

#endif

#ifdef SYNC_MMIO
        dut_getmmios(&dut_mmios);
        dut_getpcs(&dut_pcs);
        if ((dut_mmios.mycpu_mmios[0] || dut_mmios.mycpu_mmios[1] || dut_mmios.mycpu_mmios[2]) && dut->io_difftest_we) { // sync mmio data
            // int idx = -1;
            // for (int i = 0; i < 3; i++) {
            //     if (dut_mmios.mycpu_mmios[i]) {
            //         idx = i;
            //         break;
            //     }
            // }
            // printf("sync pc: [%016lx], sync wdata: [%016lx], sync reg_num: %d\n", dut_pcs.mycpu_pcs[idx], dut->io_difftest_wdata, dut->io_difftest_wdest);
            qemu_getregs(conn, &regs);
            regs.gpr[dut->io_difftest_wdest] = dut->io_difftest_wdata;
            qemu_setregs(conn, &regs);
        }
#endif

#ifdef SYNC_TIME_INT
        if (dut->io_difftest_int) {
            qemu_enable_int(conn);
        }
#endif

        qemu_getregs(conn, &regs);
        dut_getregs(&dut_regs);
        dut_getpcs(&dut_pcs);

        if (!difftest_regs(&regs, &dut_regs, &dut_pcs)) {
            sleep(1);
            printf("\nQEMU\n");
            // qemu_getmem(conn, 0x200bff8);
            // qemu_getmem(conn, 0x2004000);
            print_qemu_registers(&regs, true);
            printf("\nDUT\n");
            for (int i = 0; i < 3; i++) {
                printf("$pc_%d:0x%016lx  ", i, dut_pcs.mycpu_pcs[i]);
            }
            printf("\n");
            print_qemu_registers(&dut_regs, false);
            printf("\n");
            result = 1;
            print_total_time();
            break;
        }
    }
    END:
#ifdef WAVE_TRACE
    dut_step(3, vfp, contextp);
    vfp->close();
    delete vfp;
    delete contextp;
#endif
    ram_finish();
    qemu_disconnect(conn);

    return result;
}

int difftest(const char *path) {
    int port = 1234;
    int ppid = getpid();
    int result = 0;

    printf("Welcome to ZJV2 differential test with QEMU!\n");

    if (fork() != 0) {    // parent process
        result = difftest_body(path, port);
    } else {              // child process
        difftest_start_qemu(path, port, ppid);
    }

    return result;
}
