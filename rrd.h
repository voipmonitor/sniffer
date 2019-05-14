#ifndef RRD_H
#define RRD_H


/*****************************************************************************
 *Based on rrd tool 1.4.3 by Tobi Oetiker
 *****************************************************************************/
int vm_rrd_create_rrdheap(const char *filename);
int vm_rrd_create_rrddrop(const char *filename);
int vm_rrd_create_rrdPS(const char *filename);
int vm_rrd_create_rrdSQL(const char *filename);
int vm_rrd_create_rrdtCPU(const char *filename);
int vm_rrd_create_rrdtacCPU(const char *filename);
int vm_rrd_create_rrdmemusage(const char *filename);
int vm_rrd_create_rrdspeedmbs(const char *filename);
int vm_rrd_create_rrdcallscounter(const char *filename);
int vm_rrd_create_rrdloadaverages(const char *filename);

int vm_rrd_create(const char *filename, const char *cmdline);
int vm_rrd_update(const char *filename, const char *cmdline);

int vm_rrd_createArgs(char *aLine, char **argv);
int vm_rrd_countArgs(char *aLine);
int rrd_call(const char *aLine);

void rrd_vm_create_graph_PS_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_PSC_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_PSS_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_PSSR_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_PSSM_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_PSR_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_PSA_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_SQLq_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_SQLf_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_tCPU_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_drop_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_heap_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_speed_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_calls_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_tacCPU_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_memusage_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);
void rrd_vm_create_graph_LA_command(char *filename, char *fromatstyle, char *toatstyle, char *color, int resx, int resy, short slope, short icon, char *dstfile, char *buffer, int maxsize);



void checkCpuCount(bool silent = false);
void checkCpuHT(bool silent = false);
void checkRrdVersion(bool silent = false);

extern int verbosity;
#ifndef RRDLIB_H_4FD7D37D56A448C392AF46508C56D3CC
#define RRDLIB_H_4FD7D37D56A448C392AF46508C56D3CC


#ifdef  __cplusplus
extern    "C" {
#endif

#include <sys/types.h>  /* for off_t */

#ifndef WIN32
#include <unistd.h>     /* for off_t */
#else
#ifdef _MSC_VER
#ifndef PERLPATCHLEVEL
	typedef int mode_t;
#endif
	#define strtoll _strtoi64 
#endif
	typedef size_t ssize_t;
	typedef long off_t;
#endif 

#include <time.h>
#include <stdio.h>      /* for FILE */
#include <string.h>

/* Formerly rrd_nan_inf.h */
#ifndef DNAN
# define DNAN rrd_set_to_DNAN()
#endif

#ifndef DINF
# define DINF rrd_set_to_DINF()
#endif
    double    rrd_set_to_DNAN(
    void);
    double    rrd_set_to_DINF(
    void);
/* end of rrd_nan_inf.h */

/* Transplanted from rrd_format.h */
    typedef double rrd_value_t; /* the data storage type is
                                 * double */
/* END rrd_format.h */

/* information about an rrd file */
    typedef struct rrd_file_t {
        size_t     header_len;   /* length of the header of this rrd file */
        size_t     file_len; /* total size of the rrd file */
        size_t     pos;  /* current pos in file */
        void      *pvt;
    } rrd_file_t;

/* information used for the conventional file access methods */
    typedef struct rrd_simple_file_t {
        int       fd;  /* file descriptor of this rrd file */
#ifdef HAVE_MMAP
        char     *file_start;   /* start address of an open rrd file */
        int       mm_prot;
        int       mm_flags;
#endif
    } rrd_simple_file_t;

/* rrd info interface */
    typedef struct rrd_blob_t {
        unsigned long size; /* size of the blob */
        unsigned char *ptr; /* pointer */
    } rrd_blob_t;

    typedef enum rrd_info_type { RD_I_VAL = 0,
        RD_I_CNT,
        RD_I_STR,
        RD_I_INT,
        RD_I_BLO
    } rrd_info_type_t;

    typedef union rrd_infoval {
        unsigned long u_cnt;
        rrd_value_t u_val;
        char     *u_str;
        int       u_int;
        rrd_blob_t u_blo;
    } rrd_infoval_t;

    typedef struct rrd_info_t {
        char     *key;
        rrd_info_type_t type;
        rrd_infoval_t value;
        struct rrd_info_t *next;
    } rrd_info_t;

    typedef size_t (* rrd_output_callback_t)(
    const void *,
    size_t,
    void *);

/* main function blocks */
    int       rrd_create(
    int,
    char **);
    rrd_info_t *rrd_info(
    int,
    char **);
    rrd_info_t *rrd_info_push(
    rrd_info_t *,
    char *,
    rrd_info_type_t,
    rrd_infoval_t);
    void      rrd_info_print(
    rrd_info_t * data);
    void      rrd_info_free(
    rrd_info_t *);
    int       rrd_update(
    int,
    char **);
    rrd_info_t *rrd_update_v(
    int,
    char **);
    int       rrd_graph(
    int,
    char **,
    char ***,
    int *,
    int *,
    FILE *,
    double *,
    double *);
    rrd_info_t *rrd_graph_v(
    int,
    char **);

    int       rrd_fetch(
    int,
    char **,
    time_t *,
    time_t *,
    unsigned long *,
    unsigned long *,
    char ***,
    rrd_value_t **);
    int       rrd_restore(
    int,
    char **);
    int       rrd_dump(
    int,
    char **);
    int       rrd_tune(
    int,
    char **);
    int       rrd_modify(
    int,
    char **);
    time_t    rrd_last(
    int,
    char **);
    int rrd_lastupdate(int argc, char **argv);
    time_t    rrd_first(
    int,
    char **);
    int       rrd_resize(
    int,
    char **);
    char     *rrd_strversion(
    void);
    double    rrd_version(
    void);
    int       rrd_xport(
    int,
    char **,
    int *,
    time_t *,
    time_t *,
    unsigned long *,
    unsigned long *,
    char ***,
    rrd_value_t **);
    int       rrd_flushcached (int argc, char **argv);

    void      rrd_freemem(
    void *mem);

/* thread-safe (hopefully) */
    int       rrd_create_r(
    const char *filename,
    unsigned long pdp_step,
    time_t last_up,
    /* int no_overwrite, */
    int argc,
    const char **argv);
    int       rrd_create_r2(
    const char *filename,
    unsigned long pdp_step,
    time_t last_up,
    int no_overwrite,
    int argc,
    const char **argv);
    rrd_info_t *rrd_info_r(
    char *);
/* NOTE: rrd_update_r and rrd_update_v_r are only thread-safe if no at-style
   time specifications get used!!! */

    int       rrd_update_r(
    const char *filename,
    const char *_template,
    int argc,
    const char **argv);
    int       rrd_update_v_r(
    const char *filename,
    const char *_template,
    int argc,
    const char **argv,
    rrd_info_t * pcdp_summary);

/* extra flags */
#define RRD_SKIP_PAST_UPDATES 0x01

    int       rrd_updatex_r(
    const char *filename,
    const char *_template,
    int extra_flags,
    int argc,
    const char **argv);
    int       rrd_updatex_v_r(
    const char *filename,
    const char *_template,
    int extra_flags,
    int argc,
    const char **argv,
    rrd_info_t * pcdp_summary);
    int rrd_fetch_r (
            const char *filename,
            const char *cf,
            time_t *start,
            time_t *end,
            unsigned long *step,
            unsigned long *ds_cnt,
            char ***ds_namv,
            rrd_value_t **data);
    int       rrd_dump_r(
    const char *filename,
    char *outname);
    time_t    rrd_last_r (const char *filename);
    int rrd_lastupdate_r (const char *filename,
            time_t *ret_last_update,
            unsigned long *ret_ds_count,
            char ***ret_ds_names,
            char ***ret_last_ds);
    time_t    rrd_first_r(
    const char *filename,
    int rraindex);

    int rrd_dump_cb_r(
    const char *filename,
    int opt_header,
    rrd_output_callback_t cb,
    void *user);

/* Transplanted from rrd_parsetime.h */
    typedef enum {
        ABSOLUTE_TIME,
        RELATIVE_TO_START_TIME,
        RELATIVE_TO_END_TIME,
        RELATIVE_TO_EPOCH
    } rrd_timetype_t;

#define TIME_OK NULL

    typedef struct rrd_time_value {
        rrd_timetype_t type;
        long      offset;
        struct tm tm;
    } rrd_time_value_t;

    char     *rrd_parsetime(
    const char *spec,
    rrd_time_value_t * ptv);
/* END rrd_parsetime.h */

    typedef struct rrd_context {
        char      lib_errstr[256];
        char      rrd_error[4096];
    } rrd_context_t;

/* returns the current per-thread rrd_context */
    rrd_context_t *rrd_get_context(void);

#ifdef WIN32
/* this was added by the win32 porters Christof.Wegmann@exitgames.com */
    rrd_context_t *rrd_force_new_context(void);
#endif

int       rrd_proc_start_end(
    rrd_time_value_t *,
    rrd_time_value_t *,
    time_t *,
    time_t *);

/* HELPER FUNCTIONS */
    void      rrd_set_error(
    char *,
    ...);
    void      rrd_clear_error(
    void);
    int       rrd_test_error(
    void);
    char     *rrd_get_error(
    void);

    /* rrd_strerror is thread safe, but still it uses a global buffer
       (but one per thread), thus subsequent calls within a single
       thread overwrite the same buffer */
    const char *rrd_strerror(
    int err);

/** MULTITHREADED HELPER FUNCTIONS */
    rrd_context_t *rrd_new_context(
    void);
    void      rrd_free_context(
    rrd_context_t * buf);

/* void   rrd_set_error_r  (rrd_context_t *, char *, ...); */
/* void   rrd_clear_error_r(rrd_context_t *); */
/* int    rrd_test_error_r (rrd_context_t *); */
/* char  *rrd_get_error_r  (rrd_context_t *); */

/** UTILITY FUNCTIONS */

    long rrd_random(void);

    int rrd_add_ptr_chunk(void ***dest, size_t *dest_size, void *src,
                          size_t *alloc, size_t chunk);
    int rrd_add_ptr(void ***dest, size_t *dest_size, void *src);
    int rrd_add_strdup(char ***dest, size_t *dest_size, char *src);
    int rrd_add_strdup_chunk(char ***dest, size_t *dest_size, char *src,
                             size_t *alloc, size_t chunk);
    void rrd_free_ptrs(void ***src, size_t *cnt);

    int rrd_mkdir_p(const char *pathname, mode_t mode);

    const char * rrd_scaled_duration (const char * token,
                                      unsigned long divisor,
                                      unsigned long * valuep);

/*
 * The following functions are _internal_ functions needed to read the raw RRD
 * files. Since they are _internal_ they may change with the file format and
 * will be replaced with a more general interface in RRDTool 1.4. Don't use
 * these functions unless you have good reasons to do so. If you do use these
 * functions you will have to adapt your code for RRDTool 1.4!
 *
 * To enable the deprecated functions define `RRD_EXPORT_DEPRECATED' before
 * including <rrd_test.h>. You have been warned! If you come back to the
 * RRDTool mailing list and whine about your broken application, you will get
 * hit with something smelly!
 */
#if defined(RRD_TOOL_H_3853987DDF7E4709A5B5849E5A6204F4) || defined(RRD_EXPORT_DEPRECATED)

# if defined(RRD_TOOL_H_3853987DDF7E4709A5B5849E5A6204F4)
#  include "rrd_format.h"
# else
#  include <rrd_format.h>
# endif

#if defined(__GNUC__) && defined (RRD_EXPORT_DEPRECATED)
# define RRD_DEPRECATED __attribute__((deprecated))
#else
# define RRD_DEPRECATED          /**/
#endif
     void     rrd_free(
    rrd_t *rrd)
              RRD_DEPRECATED;
    void      rrd_init(
    rrd_t *rrd)
              RRD_DEPRECATED;

    rrd_file_t *rrd_open(
    const char *const file_name,
    rrd_t *rrd,
    unsigned rdwr)
              RRD_DEPRECATED;

    void      rrd_dontneed(
    rrd_file_t *rrd_file,
    rrd_t *rrd)
              RRD_DEPRECATED;
    int       rrd_close(
    rrd_file_t *rrd_file)
              RRD_DEPRECATED;
    ssize_t   rrd_read(
    rrd_file_t *rrd_file,
    void *buf,
    size_t count)
              RRD_DEPRECATED;
    ssize_t   rrd_write(
    rrd_file_t *rrd_file,
    const void *buf,
    size_t count)
              RRD_DEPRECATED;
    void      rrd_flush(
    rrd_file_t *rrd_file)
              RRD_DEPRECATED;
    off_t     rrd_seek(
    rrd_file_t *rrd_file,
    off_t off,
    int whence)
              RRD_DEPRECATED;
    off_t     rrd_tell(
    rrd_file_t *rrd_file)
              RRD_DEPRECATED;
    int       rrd_lock(
    rrd_file_t *file)
              RRD_DEPRECATED;
    void      rrd_notify_row(
    rrd_file_t *rrd_file,
    int rra_idx,
    unsigned long rra_row,
    time_t rra_time)
              RRD_DEPRECATED;
    unsigned long rrd_select_initial_row(
    rrd_file_t *rrd_file,
    int rra_idx,
    rra_def_t *rra
    )
              RRD_DEPRECATED;
#endif                  /* defined(_RRD_TOOL_H) || defined(RRD_EXPORT_DEPRECATED) */

#ifdef  __cplusplus
}
#endif

#endif /* RRDLIB_H */

#endif //RRD_H
