#include "file_worker.h"
FILE * open_for_read(const char *fname){
    return fopen(fname, "rb");
}

FILE * open_for_write(const char *fname){
    return fopen(fname, "wb");
}
int close(FILE* fname){
    return fclose(fname);
}
