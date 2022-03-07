#include "exe_headers.h"
#include <stdio.h>
#include <stdlib.h>

enum read_status  {
  ITS_PE_FILE = 0,
  ITS_NOT_PE_FILE = 1
  };


enum read_status parse(FILE* in, FILE* out, FILE * out2);

#pragma once 
#include <inttypes.h>





