#include "parser.h"
#include "file_worker.h"



int main( int argc, char** argv ){
    (void) argc; (void) argv;
    if (argc != 4) {
        printf("Invalid arguments\n");
        return 1;
    }

    FILE * f = open_for_read(argv[1]);
    FILE *f_w = open_for_write(argv[2]);
    FILE *f_w_bin = open_for_write(argv[3]);
    if(f&&f_w&&f_w_bin) {
        parse(f,f_w,f_w_bin);
        return 0;
    }
    else {
        printf("Unable to find such file or directory");
        return 1;
    }
}

