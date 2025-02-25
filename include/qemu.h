#ifndef QEMU_H
#define QEMU_H

#include <stdbool.h>
#include "gdb_proto.h"
#include "isa.h"

typedef struct gdb_conn qemu_conn_t;

int qemu_start(const char *elf, int port);

qemu_conn_t *qemu_connect(int port);

void qemu_disconnect(qemu_conn_t *conn);

// bool qemu_memcpy_to_qemu_small(qemu_conn_t *conn, uint32_t dest, void *src, int len);

// bool qemu_memcpy_to_qemu(qemu_conn_t *conn, uint32_t dest, void *src, int len);

void qemu_getregs(qemu_conn_t *conn, qemu_regs_t *r);

bool qemu_setregs(qemu_conn_t *conn, qemu_regs_t *r);

bool qemu_single_step(qemu_conn_t *conn);

void qemu_break(qemu_conn_t *conn, uint64_t entry);

void qemu_remove_breakpoint(qemu_conn_t *conn, uint64_t entry);

void qemu_continue(qemu_conn_t *conn);

inst_t qemu_getinst(qemu_conn_t *conn, uint32_t pc);

bool qemu_setinst(qemu_conn_t *conn, uint32_t pc, inst_t *inst);

uint64_t qemu_getmem(qemu_conn_t *conn, uint32_t addr);

uint64_t qemu_read_mem(qemu_conn_t *conn, uint32_t addr, int nbyte);

void qemu_getcsrs(qemu_conn_t *conn, qemu_regs_t *r);

void qemu_get_csr(qemu_conn_t *conn, int csr_num, uint64_t *csr_data);

void qemu_getfprs(qemu_conn_t *conn, qemu_regs_t *r);

bool qemu_set_csr(qemu_conn_t *conn, int csr_num, uint64_t *data);

void qemu_init(qemu_conn_t *conn);

void qemu_disable_int(qemu_conn_t *conn);

void qemu_enable_int(qemu_conn_t *conn);

void qemu_zero_csr_wpri(qemu_conn_t *conn);

#endif
