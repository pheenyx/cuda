#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <getopt.h>
#include <math.h>
#define THREADS_PER_BLOCK 4
//
char* strInputFileName;
int N;
int isSerial = 0;
int verbose = 0;
//
void checkCUDAError(const char *msg);
void parseArgs(int argc, char** argv);
void displayData(int* data, int size);
void loadData(int* data,char* fileName,int nElement);
void cudaFunction(int* inputData,int n);
void serialFunction(int* inputData,int n);
//example: the scan kernel
__global__ void scan(int* inputData, int* outputData, int n)
{
    extern __shared__ int sdata[];
    // each thread loads one element from global to shared mem
    unsigned int tid = threadIdx.x;
    int pout = 0, pin = 1;
    // Load input into shared memory.
    // exclusive scan, so shift right by one and set first elt to 0
    int prevElt;
    prevElt = (blockIdx.x == 0 ? 0 : blockIdx.x*n - 1);
    sdata[pout*n + tid] = (tid > 0) ? inputData[blockIdx.x*n + tid - 1] : prevElt;
    //sdata[n + tid] = (tid > 0) ? inputData[blockIdx.x*n + tid - 1] : 0;
    __syncthreads();
    // do scan in shared mem
    for(unsigned int offset = 1; offset < n; offset *= 2) {

        pout = 1 - pout;
        pin = 1 - pin;
        if (tid >= offset) {
            printf("pout: %i  pin: %i  offset: %i  added in if  : %i [%i] to %i [%i] \n", pout, pin, offset, sdata[pin*n+tid - offset], pin*n+tid - offset , sdata[pout*n+tid], pout*n+tid);
            sdata[pout*n + tid] = sdata[pin*n+tid] + sdata[pin*n + tid - offset];
        } else {
            printf("pout: %i  pin: %i  offset: %i  added in else: %i [%i] to %i [%i]\n", pout, pin, offset, sdata[pin*n+tid],pin*n+tid , sdata[pout*n+tid], pout*n+tid);
            sdata[pout*n + tid] = sdata[pin*n + tid];
        }
        __syncthreads();
        if (tid == 0){
            for (int i = 0; i<2*n;++i){
                printf("%i\t",sdata[i]);
            }
            printf("\n");
        }
    }
    // write result for this block to global mem
    outputData[blockIdx.x*n + tid] = sdata[pout*n + tid];
}

//}

int main(int argc, char** argv)
{
  int* inputData;
  //
  parseArgs(argc,argv);
  //find the next power of 2 to allocate the array
  int nextPowOf2;
  if (!(N==0) && !(N & (N-1))){
    nextPowOf2 = N;
  } else {
    nextPowOf2 = (int)pow(2,ceil(log2((double)N)));
  }
  inputData = (int*) malloc(sizeof(int)*nextPowOf2);
  //load n element from the input file
  loadData(inputData,strInputFileName,N);
  //display the input data, just use with the small data, to test
  if (verbose) {
    printf("Input data:\n");
    displayData(inputData,N);
    printf("\n");
  }
  //
  if(isSerial == 0)
  {
    // pad the rest of inputData with 0
    for (int i = N; i<nextPowOf2; ++i){
        inputData[i] = 0;
    }
    N = nextPowOf2;
    printf("Running the CUDA implementation\n");
    cudaFunction(inputData,N);
    //
  }
  else
  {
    printf("Running the serial implementation\n");
    serialFunction(inputData,N);
  }
  //
  free(inputData);
  free(strInputFileName);
  //
  return 0;
}
//
void cudaFunction(int* inputData,int N)
{
  //the CUDA implementation here 
  int threadsPerBlock;
  int blocksPerGrid;
  int* device_input;
  int* device_output;
  int* host_output;
  int nLeft  = N;
  cudaEvent_t start, stop;
  float elapsedTime;
  unsigned int sharedSize;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  //
  cudaMalloc(&device_input, sizeof(int)*N); 
  cudaMalloc(&device_output, sizeof(int)*N); 
  host_output = (int*)malloc(sizeof(int)*N);
  //
  cudaEventRecord(start,0);
  cudaMemcpy(device_input,inputData,sizeof(int)*N,cudaMemcpyHostToDevice); 
  checkCUDAError("cudaMemcpy: host to device");
  //
  //sharedSize = N*sizeof(int);

  while (nLeft > 1){
    
    threadsPerBlock = (nLeft > THREADS_PER_BLOCK ? THREADS_PER_BLOCK : nLeft);
    blocksPerGrid = (nLeft > THREADS_PER_BLOCK ? nLeft/THREADS_PER_BLOCK : 1);
    sharedSize = threadsPerBlock*sizeof(int);
    scan<<<blocksPerGrid,threadsPerBlock,2*sharedSize>>>(device_input, device_output, threadsPerBlock); 
    nLeft = blocksPerGrid;
    cudaMemcpy(device_input, device_output, sizeof(int)*N, cudaMemcpyDeviceToDevice);
  }
  
  cudaDeviceSynchronize();
  checkCUDAError("kernel lauching");
  //use host_output to get the output from the kernel, 
  //the last element is the scan result
  cudaMemcpy(host_output,device_output,sizeof(int)*N,cudaMemcpyDeviceToHost); 
  checkCUDAError("cudaMemcpy: device to host");
  //
  cudaEventRecord(stop,0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime,start,stop);
  printf("the scan result is : %d\n",host_output[N-1]);
  printf("Elapsed time is: %f\n",elapsedTime);
  //
  cudaEventDestroy(start);
  cudaEventDestroy(stop);
  cudaFree(device_input);
  cudaFree(device_output);
}
//
void serialFunction(int* inputData,int N)
{
  cudaEvent_t start, stop;
  float elapsedTime;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  cudaEventRecord(start,0);
  //the serial implementation here
  long sum = 0;
  for (int i = 0; i < N; ++i){
    sum += inputData[i];
  }
  cudaEventRecord(stop,0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime,start,stop);
  printf("the serial scan result is : %ld\n",sum);
  printf("Elapsed time is: %f\n",elapsedTime);
  cudaEventDestroy(start);
  cudaEventDestroy(stop);

}
//
void loadData(int* data,char* fileName,int nElement)
{
  FILE* fin;
  fin = fopen(fileName,"r");
  if(fin==NULL)
  {
    printf("Can not open %s\n",fileName);
    exit(1);
  }
  //
  fread(data,sizeof(int),nElement,fin);
  //
  fclose(fin);
}
//
void displayData(int* data, int size)
{
  int i;
  for(i=0;i<size;++i) printf("%d ",data[i]);
}
//
//function to check cuda error, cited from 
//http://www.drdobbs.com/parallel/cuda-supercomputing-for-the-masses-part/207603131?pgno=2
void checkCUDAError(const char *msg)
{
    cudaError_t err = cudaGetLastError();
    if( cudaSuccess != err) 
    {
        fprintf(stderr, "Cuda error: %s: %s.\n", msg, 
                                  cudaGetErrorString( err) );
        exit(EXIT_FAILURE);
    }                         
}
void parseArgs(int argc, char** argv)
{
  char c;
  int optionIndex = 0;
  struct option longOption[]=
  {
    {"inputfile",1,NULL,'i'},
    {"number",1,NULL,'n'},
    {"serial",1,NULL,'s'},
    {"verbose",1,NULL,'v'},
    {0,0,0,0}
  };
  if (argc < 5) 
  {
    printf("Wrong number of arguments\n");
    exit(1);
  }
  while((c=getopt_long(argc,argv,"n:i:sv",longOption,&optionIndex))!=-1)
  {
    switch(c)
    {
      case 'i':
	    strInputFileName = strdup(optarg);
	    break;
      case 'n':
	    N = atoi(optarg);
	    break;
      case 's':
        isSerial = 1;
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

