

#################################################################################################

# Indicator Matrix 

###################################################################################################

# read in data
df1999_2004 <- read.csv("/IndicatorMatrices/1999-2004indicator_dataframe.csv")

df1999_2004

indic_matrix <- data.matrix(df1999_2004)
indic_matrix
indic_matrix<-indic_matrix[,-1]
dim(indic_matrix)

#################################################################################################

#
# biclust 
#
#install.packages("biclust")
library("biclust")

#
# BCBimax: searches for submatrices of ones in a logical(binary) matrix
bics<-biclust(indic_matrix, method=BCBimax(), minr=2, minc=2,number=10)
biclustbarchart(indic_matrix,bics)
ord<-bicorder(bics, cols=TRUE, rev=TRUE)
biclustbarchart(indic_matrix,bics,which=ord)
biclustmember(bics,indic_matrix)
ord<-bicorder(bics, cols=TRUE, rev=TRUE)
biclustmember(bics,indic_matrix,which=ord)
heatmapBC(x = indic_matrix, bicResult = bics,which=ord)

out <- diagnosticTest(BCresult=bics, data=indic_matrix, save_F=TRUE, statistics=c("F"),
                      samplingtypes=c("Permutation","SemiparPerm","SemiparBoot",
                                      "PermutationCor","SamplingCor","NormSim"))

out[[2]]$table
computeObservedFstat(indic_matrix, bics, 1)
Bootstrap <- diagnoseColRow(x=indic_matrix, bicResult = bics, number = 1, 
                            nResamplings = 999, replace = TRUE)

# plotting distribution of bootstrap replicates
diagnosticPlot(bootstrapOutput = Bootstrap) 	

##################################################################################################

#
#sigclust
#
library("sigclust")

nsim <- 1000
nrep <- 1
icovest <- 3

# Perform a significance analysis of clustering, studies whether clusters are really there
# assesses the significance of clustering by simulation from a single null Gaussian distribution.
pvalue <- sigclust(indic_matrix,nsim=nsim,nrep=nrep,labflag=0,icovest=icovest)
plot(pvalue)


# Indicator Matrix : 2005-2010

###################################################################################################

# read in data
df2 <- read.csv("/IndicatorMatrices/2005-2007indicator_dataframe.csv")
df3 <- read.csv("/IndicatorMatrices/2008-2010indicator_dataframe.csv")

#df[is.na(df)] = 0

df2
df3

df2005_2010 <- cbind(df2, df3)
df2005_2010

indic_matrix2005_2010 <- data.matrix(df2005_2010)
indic_matrix2005_2010<-indic_matrix2005_2010[,-1]
indic_matrix2005_2010<-indic_matrix2005_2010[,-37]
dim(indic_matrix2005_2010)

#################################################################################################

#
# biclust 
#
#install.packages("biclust")
library("biclust")

#
# BCBimax: searches for submatrices of ones in a logical(binary) matrix
bics<-biclust(indic_matrix2005_2010, method=BCBimax(), minr=2, minc=2,number=10)
biclustbarchart(indic_matrix2005_2010,bics)
ord<-bicorder(bics, cols=TRUE, rev=TRUE)
drawHeatmap(indic_matrix2005_2010,bics,1,plotAll = TRUE)
biclustmember(bics,indic_matrix2005_2010)
heatmapBC(x = indic_matrix2005_2010, bicResult = bics)

Bootstrap <- diagnoseColRow(x=indic_matrix2005_2010, bicResult = plaidmab, number = 1, 
                            nResamplings = 999, replace = TRUE)


##################################################################################################

#
#sigclust
#
library("sigclust")

nsim <- 1000
nrep <- 1
icovest <- 3

# Perform a significance analysis of clustering, studies whether clusters are really there
# assesses the significance of clustering by simulation from a single null Gaussian distribution.
pvalue <- sigclust(indic_matrix2005_2010,nsim=nsim,nrep=nrep,labflag=0,icovest=icovest)
plot(pvalue)


# Indicator Matrix : 2011-2016

###################################################################################################

# read in data
df1 <- read.csv("/IndicatorMatrices/2011-2012indicator_dataframe.csv")
df2 <- read.csv("/IndicatorMatrices/2013-2014indicator_dataframe.csv")
df3 <- read.csv("/IndicatorMatrices/2015-2016indicator_dataframe.csv")


df2011_2016 <- cbind(df1, df2,df3)
df2011_2016

indic_matrix2011_2016 <- data.matrix(df2011_2016)
indic_matrix2011_2016<-indic_matrix2011_2016[,-1]
indic_matrix2011_2016<-indic_matrix2011_2016[,-25]
indic_matrix2011_2016<-indic_matrix2011_2016[,-49]
dim(indic_matrix2011_2016)

#################################################################################################

#
# biclust 
#
#install.packages("biclust")
library("biclust")

#
# BCBimax: searches for submatrices of ones in a logical(binary) matrix
#biclust(indic_matrix, method=BCBimax(), minr=2, minc=2, number=100)
bics<-biclust(indic_matrix2011_2016, method=BCBimax(), minr=2, minc=2,number=10)
biclustbarchart(indic_matrix2011_2016,bics)
ord<-bicorder(bics, cols=TRUE, rev=TRUE)
drawHeatmap(indic_matrix2011_2016,bics,1,plotAll = TRUE)
biclustmember(bics,indic_matrix2011_2016)
heatmapBC(x = indic_matrix2011_2016, bicResult = bics)

##################################################################################################

#
#sigclust
#
library("sigclust")

nsim <- 1000
nrep <- 1
icovest <- 3

# Perform a significance analysis of clustering, studies whether clusters are really there
# assesses the significance of clustering by simulation from a single null Gaussian distribution.
pvalue <- sigclust(indic_matrix2011_2016,nsim=nsim,nrep=nrep,labflag=0,icovest=icovest)
plot(pvalue)



# Indicator Matrix : 2017-2021

###################################################################################################

# read in data
df1 <- read.csv("/IndicatorMatrices/2017indicator_dataframe.csv")
df2 <- read.csv("/IndicatorMatrices/2018indicator_dataframe.csv")
df3 <- read.csv("/IndicatorMatrices/2019indicator_dataframe.csv")
df4 <- read.csv("/IndicatorMatrices/2020indicator_dataframe.csv")
df5 <- read.csv("/IndicatorMatrices/2021indicator_dataframe.csv")


df2017_2021 <- cbind(df1, df2,df3,df4,df5)
df2017_2021

indic_matrix2017_2021 <- data.matrix(df2017_2021)
indic_matrix2017_2021<-indic_matrix2017_2021[,-1]
indic_matrix2017_2021<-indic_matrix2017_2021[,-13]
indic_matrix2017_2021<-indic_matrix2017_2021[,-25]
indic_matrix2017_2021<-indic_matrix2017_2021[,-37]
indic_matrix2017_2021<-indic_matrix2017_2021[,-49]
dim(indic_matrix2017_2021)

#################################################################################################

#
# biclust 
#
#install.packages("biclust")
library("biclust")

#
# BCBimax: searches for submatrices of ones in a logical(binary) matrix

bics<-biclust(indic_matrix2017_2021, method=BCBimax(), minr=2, minc=2,number=10)
biclustbarchart(indic_matrix2017_2021,bics)
ord<-bicorder(bics, cols=TRUE, rev=TRUE)
drawHeatmap(indic_matrix2017_2021,bics,1,plotAll = TRUE)
biclustmember(bics,indic_matrix2017_2021)
heatmapBC(x = indic_matrix2017_2021, bicResult = bics)


##################################################################################################

#
#sigclust
#
library("sigclust")

nsim <- 1000
nrep <- 1
icovest <- 3

# Perform a significance analysis of clustering, studies whether clusters are really there
# assesses the significance of clustering by simulation from a single null Gaussian distribution.
pvalue <- sigclust(indic_matrix2017_2021,nsim=nsim,nrep=nrep,labflag=0,icovest=icovest)
plot(pvalue)


# read in data

df_all <- cbind(df1999_2004,df2005_2010,df2011_2016,df2017_2021)
df_all

indic_matrixall <- data.matrix(df_all)

indic_matrixall<-indic_matrixall[,-1]
indic_matrixall<-indic_matrixall[,-73]
indic_matrixall<-indic_matrixall[,-109]
indic_matrixall<-indic_matrixall[,-145]
indic_matrixall<-indic_matrixall[,-169]
indic_matrixall<-indic_matrixall[,-193]
indic_matrixall<-indic_matrixall[,-217]
indic_matrixall<-indic_matrixall[,-229]
indic_matrixall<-indic_matrixall[,-241]
indic_matrixall<-indic_matrixall[,-253]
indic_matrixall<-indic_matrixall[,-265]



dim(indic_matrixall)

#################################################################################################

#
# biclust 
#
#install.packages("biclust")
library("biclust")

#
# BCBimax: searches for submatrices of ones in a logical(binary) matrix

bics<-biclust(indic_matrixall, method=BCBimax(), minr=2, minc=2,number=10)
biclustbarchart(indic_matrixall,bics)
ord<-bicorder(bics, cols=TRUE, rev=TRUE)
drawHeatmap(indic_matrixall,bics,1,plotAll = TRUE)
biclustmember(bics,indic_matrixall)
heatmapBC(x = indic_matrixall, bicResult = bics)

##################################################################################################

#
#sigclust
#
library("sigclust")

nsim <- 1000
nrep <- 1
icovest <- 3

# Perform a significance analysis of clustering, studies whether clusters are really there
# assesses the significance of clustering by simulation from a single null Gaussian distribution.
pvalue <- sigclust(indic_matrixall,nsim=nsim,nrep=nrep,labflag=0,icovest=icovest)
plot(pvalue)

