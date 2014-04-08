#include <stdio.h>

__global__ void sayhello() {
  printf("Hello I'm thread %i, on block %i\n",threadIdx.x,blockIdx.x);
}

int main(int argc, char**argv) {


    int blocksPerGrid;
    int threadsPerBlock;
    // setup number of thread and block: for test
    //int blocksPerGrid = 1;
    //int threadsPerBlock = 1;
    // read the number of thread and block from the command line
    blocksPerGrid = atoi(argv[1]);
    threadsPerBlock = atoi(argv[2]);
    printf("blocksPerGrid = %d, threadsPerBlock = %d\n",blocksPerGrid,threadsPerBlock);
    // cuda kernel call here
    sayhello<<<blocksPerGrid,threadsPerBlock>>>();
    // wait for gpu to complete
    cudaDeviceSynchronize();

    return 0;
}
