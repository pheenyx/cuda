/*
  The Johannes University of Mainz
  CUDA Practical, Winter Term 2013/14
  The solution for the exercise of implementation of 
  parallel reduction algorithm
  group member: Tassilo Kugelstadt and Denise Scherzinger
*/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <getopt.h>
#include <math.h>
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
__global__ void reduction1(int* inputData, int* outputData , int n){
  extern __shared__ int sdata[];
  //load elements from global into shared memory
  int tid = threadIdx.x;
  int i = blockDim.x * blockIdx.x + threadIdx.x;
  sdata[tid] = inputData[i];
  __syncthreads();
  //do reduction
  for(int s=1; s<blockDim.x; s*=2){
	//first alg
	if(tid % (2*s)==0){
		sdata[tid] += sdata[tid+s];
	}
	__syncthreads();
  }
  //write result back to global memory
  if(tid==0) outputData[blockIdx.x] = sdata[0];
}
__global__ void reduction2(int* inputData, int* outputData , int n)
{
  //implement the reduction here
  extern __shared__ int sdata[];  
  //load elements from global into shared memory
  int tid = threadIdx.x;
  int i = blockDim.x * blockIdx.x + threadIdx.x;
  sdata[tid] = inputData[i];
  __syncthreads();
  //do reduction
  for(int s=1; s<blockDim.x; s*=2){
	int index = 2 * s * tid;
	if(index < blockDim.x){
		sdata[index] += sdata[index+s];
	}
	__syncthreads();
  }
  //write result back to global memory
  if(tid==0) outputData[blockIdx.x] = sdata[0];
}

int main(int argc, char** argv)
{
  int* inputData;
  //
  parseArgs(argc,argv);
  //if N is not the power of 2:
  //   + change to the nearest power of 2
  //   + pad the extend element with 0
  int realBase = ceil(log(N)/log(2));
  int realN = (int) pow(2,realBase);
  printf("realN = %d\n",realN);
  inputData = (int*) malloc(sizeof(int)*realN);
  //padding
  for(int i=N;i<realN;++i) inputData[i] = 0;
  N = realN;
  //end of padding
  //load n element from the input file
  loadData(inputData,strInputFileName,N);
  //display the input data, just use with the small data, to test
  printf("Input data:\n");
  //displayData(inputData,N);
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
  int* device_output;
  int* host_output;
  cudaEvent_t start, stop;
  float elapsedTime;
  unsigned int sharedSize;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  //
  cudaEventRecord(start,0);
  threadsPerBlock = 1024;
  blocksPerGrid = (N + threadsPerBlock - 1)/1024;
  //
  int* temp;
  int loopCount = 0;
  temp = inputData;
  cudaMalloc(&device_input, sizeof(int)*N);
  cudaMalloc(&device_output, sizeof(int)*blocksPerGrid);  
  host_output = (int*)malloc(sizeof(int)*N);
  do
  {
	cudaMemcpy(device_input,temp,sizeof(int)*N,cudaMemcpyHostToDevice); 
	checkCUDAError("cudaMemcpy: host to device");
	blocksPerGrid = (N + threadsPerBlock - 1)/1024;
	if(N < 1024) threadsPerBlock = N;
	sharedSize = threadsPerBlock*sizeof(int);
	printf("loopCount = %d, N = %d, threadsPerBlock = %d, blocksPerGrid = %d \n",loopCount+1,N,threadsPerBlock,blocksPerGrid);
	reduction2<<<blocksPerGrid,threadsPerBlock,sharedSize>>>(device_input, device_output, N);
	cudaDeviceSynchronize();
	checkCUDAError("kernel lauching");
	//use host_output to get the output from the kernel, 
	//the last element is the reduction result
	cudaMemcpy(host_output,device_output,sizeof(int)*blocksPerGrid,cudaMemcpyDeviceToHost); 
	checkCUDAError("cudaMemcpy: device to host");
	temp = host_output;
	N = blocksPerGrid;
	printf("Finish the %d loop\n",loopCount);
	loopCount++;
	//for(int j=0;j<N;++j) printf("%d ",temp[j]);
  }while(blocksPerGrid > 1);
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
  cudaEvent_t start, stop;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  float elapsedTime;
  cudaEventRecord(start,0);
  int i;
  int output = 0;
  for(i=0; i< N; i++)
	output+= inputData[i];
  cudaEventRecord(stop,0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime,start,stop);
  printf("the reduction result is : %d\n",output);
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
  //fseek(fin,2048*sizeof(int),SEEK_SET);
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

