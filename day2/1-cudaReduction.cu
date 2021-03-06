#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <getopt.h>
//
char* strInputFileName;
int N;
int isSerial = 0;
//
void checkCUDAError(const char *msg);
void parseArgs(int argc, char** argv);
void displayData(int* data, int size);
void loadData(int* data,char* fileName,int nElement);
void cudaFunction(int* inputData,int n);
void serialFunction(int* inputData,int n);
//example: the reduction kernel
__global__ void reduction(int* inputData, int n)
{
    //__global__ void reduce0(int *g_idata, int *g_odata) {
    extern __shared__ int sdata[];
    // each thread loads one element from global to shared mem
    unsigned int tid = threadIdx.x;
    unsigned int i = blockIdx.x*blockDim.x + threadIdx.x;
    sdata[tid] = inputData[i];
    __syncthreads();
    // do reduction in shared mem
    for(unsigned int s=1; s < blockDim.x; s *= 2) {
        if (tid % (2*s) == 0) {
            sdata[tid] += sdata[tid + s];
        }
        __syncthreads();
    }
    // write result for this block to global mem
    if (tid == 0) inputData[blockIdx.x] = sdata[0];
}

//}

int main(int argc, char** argv)
{
  int* inputData;
  //
  parseArgs(argc,argv);
  //
  inputData = (int*) malloc(sizeof(int)*N);
  //load n element from the input file
  loadData(inputData,strInputFileName,N);
  //display the input data, just use with the small data, to test
  printf("Input data:\n");
  displayData(inputData,N);
  printf("\n");
  //
  if(isSerial == 0)
  {
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
  int* host_output;
  cudaEvent_t start, stop;
  float elapsedTime;
  unsigned int sharedSize;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  //
  cudaMalloc(&device_input, sizeof(int)*N); 
  host_output = (int*)malloc(sizeof(int)*N);
  //
  cudaEventRecord(start,0);
  cudaMemcpy(device_input,inputData,sizeof(int)*N,cudaMemcpyHostToDevice); 
  checkCUDAError("cudaMemcpy: host to device");
  //
  sharedSize = N*sizeof(int);
  threadsPerBlock = N;
  blocksPerGrid = 1;
  reduction<<<blocksPerGrid,threadsPerBlock,sharedSize>>>(device_input, N); 
  cudaDeviceSynchronize();
  checkCUDAError("kernel lauching");
  //use host_output to get the output from the kernel, 
  //the last element is the reduction result
  cudaMemcpy(host_output,device_input,sizeof(int)*N,cudaMemcpyDeviceToHost); 
  checkCUDAError("cudaMemcpy: device to host");
  //
  cudaEventRecord(stop,0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime,start,stop);
  printf("the reduction result is : %d\n",host_output[0]);
  printf("Elapsed time is: %f\n",elapsedTime);
  //
  cudaEventDestroy(start);
  cudaEventDestroy(stop);
}
//
void serialFunction(int* inputData,int N)
{
  //the serial implementation here
  int sum =0;
  for (int i = 0; i < N; ++i){
    sum += inputData[i];
  }
  printf("the serial reduction result is : %d\n",sum);

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
    {"input-file",1,NULL,'i'},
    {"number",1,NULL,'n'},
    {"is-serial",1,NULL,'s'},
    {0,0,0,0}
  };
  if (argc < 5) 
  {
    printf("Wrong number of arguments\n");
    exit(1);
  }
  while((c=getopt_long(argc,argv,"n:i:s",longOption,&optionIndex))!=-1)
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
      default:
	printf("Bad argument %c\n",c);
	exit(1);
    }
  }    
}

