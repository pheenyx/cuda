#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<getopt.h>
char* strFileName;
int N;
int verbose = 0;
__global__ void square(int *array,int N) {
  // calculate global thread id and total number of threads
  // threadIdx.x = 0..blockDim.x
  // blockIdx.x = 0..gridDim.x
  int total_threads = N; //fix this
  int global_id = blockDim.x * blockIdx.x + threadIdx.x;
  int tid, a;
  for (tid=global_id;tid<N;tid+=total_threads) 
  {
      a = array[tid];
      a = a*a;
      array[tid]=a;
  }
}

void checkCUDAError(const char *msg){
        cudaError_t err = cudaGetLastError();
        if ( cudaSuccess != err) {
           fprintf(stderr, "Cuda error: %s: %s.\n", msg, cudaGetErrorString( err) );
           exit(EXIT_FAILURE);
        }
}

void loadData(int* data,char* fileName)
{
  FILE* fin;
  fin = fopen(fileName,"r");
  if(fin==NULL)
  {
    printf("Can not open %s\n",fileName);
    exit(1);
  }
  //
  fread(data,sizeof(int),N,fin);
  //
  fclose(fin);
}

void parseArgs(int argc, char** argv)
{
  char c;
  int optionIndex = 0;
  struct option longOption[]=
  {
    {"filename",1,NULL,'f'},
    {"number",1,NULL,'n'},
    {"verbose",1,NULL,'v'},
    {0,0,0,0}
  };
  if (argc < 5) 
  {
    printf("Wrong number of arguments\n");
    exit(1);
  }
  while((c=getopt_long(argc,argv,"n:f:v",longOption,&optionIndex))!=-1)
  {
    switch(c)
    {
      case 'f':
        strFileName = strdup(optarg);
        break;
      case 'n':
        N = atoi(optarg);
        break;
      case 'v':
        verbose = 1;
        break;
      default:
        printf("Bad argument %c\n",c);
        exit(1);
    }
  }
}

int main(int argc, char**argv) {
  int *host_array, *device_array;
  int i;
  int blocksPerGrid, threadsPerBlock;
  cudaEvent_t start, stop;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  float kernelTime, copyTime1, copyTime2;
  //N = atoi(argv[1]);
  parseArgs(argc, argv);
  printf("Number of elements inside array: %d\n",N);

  // malloc host memory (cpu memory)
  host_array = (int*) malloc(sizeof(int)*N);
  loadData(host_array, strFileName);

  //display input array
  if(verbose) for(i=0;i<N;++i) printf("%d  ",host_array[i]);
  //
  threadsPerBlock = 1024;
  blocksPerGrid = (int)ceil((double) N/threadsPerBlock);

  // malloc device memory (gpu memory)
  cudaMalloc(&device_array, N*sizeof(int));
  checkCUDAError("malloc");
  
  // copy memory from host to device
  cudaEventRecord(start, 0);
  cudaMemcpy(device_array,host_array,N*sizeof(int),cudaMemcpyHostToDevice);
  checkCUDAError("memcpy");
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&copyTime1, start, stop);
 

    printf("debug: %i\n",blocksPerGrid);

  // call square kernel
  cudaEventRecord(start, 0);
  square<<<blocksPerGrid,threadsPerBlock>>>(device_array, N);
  checkCUDAError("square function");
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&kernelTime, start, stop);

  cudaDeviceSynchronize();
  checkCUDAError("syncronize");

  // copy back result to host
  cudaEventRecord(start, 0);
  cudaMemcpy(host_array,device_array,N*sizeof(int),cudaMemcpyDeviceToHost);
  checkCUDAError("memcpy2");
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&copyTime2, start, stop);

  if (verbose) {
    printf("\nResults:\n");
    for (i=0;i<N;i++) printf("%d  ",host_array[i]);
    printf("\n");
  }
  printf("Times:\n");
  printf("copy1: %f\t exec: %f\t copy2: %f\n",copyTime1, kernelTime, copyTime2);
  //

  free(host_array);
  cudaFree(device_array);
  checkCUDAError("free");
  return 0;
}
