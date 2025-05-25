#!/usr/bin/env python
# coding: utf-8

# # Imports

# In[2]:


from lxml import etree
import xml.etree.ElementTree as ET
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import pandas as pd
import numpy as np
import csv
from numpy import asarray
from numpy import savetxt


# # Pre-Processing

# In[3]:


# reads in the CVE data sets and returns vulnerability information  

def read_files(files):
    all_entries = {0: {'CVE': "", 'Date': "",'Description': [], 'Description-Tokenized' : [],
                   'Month-String':"",'Month-Int': 0,"Year":"","Year-Int":0,"Cluster": 0,
                    "Time Start": 0, "Time End": 0}}
    
    untokenized_text = list()
    start_index = 0
    year_num = 1
    
    for file in files:
        vulns = parse_data(file)
        for text in vulns[1]:
            untokenized_text.append(text)
        cur_entries = store_entries(vulns,start_index,year_num,len(files))
        start_index = len(cur_entries) + start_index
        all_entries = all_entries | cur_entries
        year_num = year_num + 1
        
    return [all_entries,untokenized_text] 
        
# helper method used to identify "REJECT" entries 

def is_member(target, possible):
    for item in possible:
        if target is item or target == item:
              return True
    return False

# parse CVE dataset in a hierarchical format

def parse_data(file):
    tree = ET.parse(file)
    root = tree.getroot()
    notes = list()
    cve = list()
    pub = list()
    for i in range(5,len(root)):
        try:
            #print(i)
            token = word_tokenize(root[i][1][0].text)
            if is_member("REJECT",token) == False:  
                pub.append(root[i][1][1].text)
                cve.append(root[i][2].text)
                notes.append(root[i][1][0].text)
        except:
            continue
    
    vulns_info = [cve,notes,pub]
    return vulns_info
            
# methods for tokenizing     
    
def tokenize(text):
    tokenized = list()
    for i in range(0, len(text)):
        filtered = remove_stopwords(word_tokenize(text[i]))
        tokenized.append(filtered)
                         
    return tokenized

def tokenize_single(sentence):
    filtered = remove_stopwords(word_tokenize(sentence))
    tokenized = [word.lower() for word in filtered] 
    return tokenized

# method to remove stopwords and punctuation

def remove_stopwords(text):
    stop_words = stopwords.words('english')
    stop_words.append(')')
    stop_words.append('(')
    stop_words.append('.')
    stop_words.append('')
    filtered_sentence = [w for w in text if not w.lower() in stop_words]
    filtered_sentence = []
 
    for w in text:
        if w not in stop_words:
            filtered_sentence.append(w)
    return filtered_sentence

# read vulnerability text for doc2vec model training 

def read_corpus(text, tokens_only=False):
    count=0
    for doc in text:
        count+=1
        tokens = gensim.utils.simple_preprocess(doc)
        if tokens_only:
            yield tokens
        else:
            yield gensim.models.doc2vec.TaggedDocument(tokens, [count])

            
# build and train a doc2vec model on all vulnerability text          
            
def build_doc2vec(untokenized_text):
    train_corpus = list(read_corpus(untokenized_text))
    test_corpus = list(read_corpus(untokenized_text, tokens_only=True))
    model = gensim.models.doc2vec.Doc2Vec(vector_size=100, min_count=2, epochs=20)
    model.build_vocab(train_corpus)
    model.train(train_corpus, total_examples=model.corpus_count, epochs=model.epochs)
    return model


# converts the vulnerability text to vectors. text is a list of tokenized sentences for the entire data set
# model is a doc2vec model 
 
def compute_vectors(text,model):
    vectors = list()
    for sentence in text:
        vectors.append(model.infer_vector(sentence))
    return vectors
        
    
# store information of each vulnerability entry in a dictionary. Includes CVE ID, Publication date, vulnerability
# description, tokenized description, month as a string, and month as an int (1-12)
    
def store_entries(vulns,start_index,year_num,total_years):
    # Create dictionaries for every year 
    entries = {start_index: {'CVE': "", 'Date': "",'Description': [], 'Description-Tokenized' : [],
                   'Month-String':"",'Month-Int': 0,"Year":"","Year-Int":0,"Time Start": 0, "Time End": 0}}
    j=0

    for i in range(start_index,start_index+len(vulns[0])):
        entries[i] = {}
        entries[i]['CVE'] = vulns[0][j]
        entries[i]['Date'] = vulns[2][j]
        entries[i]['Description'] = vulns[1][j]
        tokenized = tokenize_single(vulns[1][j])
        desc_tokenized = remove_stopwords(tokenized)
        entries[i]['Description-Tokenized'] = desc_tokenized
        entries[i]['Month-String'] = "n/a"
        entries[i]['Month-Int'] = 0
        entries[i]["Year"] = entries[i]['Date'][0:4]
        entries[i]["Year-Int"] = year_num
        j = j + 1

    for i in range(start_index,start_index+len(vulns[0])):
        if str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '1':
            entries[i]["Month-String"] = "January"
            entries[i]["Month-Int"] = 1
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '2':
            entries[i]["Month-String"] = "February"
            entries[i]["Month-Int"] = 2
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '3':
            entries[i]["Month-String"] = "March"
            entries[i]["Month-Int"] = 3
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '4':
            entries[i]["Month-String"] = "April"
            entries[i]["Month-Int"] = 4
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '5':
            entries[i]["Month-String"] = "May"
            entries[i]["Month-Int"] = 5
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '6':
            entries[i]["Month-String"] = "June"
            entries[i]["Month-Int"] = 6
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '7':
            entries[i]["Month-String"] = "July"
            entries[i]["Month-Int"] = 7
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '8':
            entries[i]["Month-String"] = "August"
            entries[i]["Month-Int"] = 8
        elif str(entries[i]['Date'])[5] == '0' and entries[i]['Date'][6] == '9':
            entries[i]["Month-String"] = "September"
            entries[i]["Month-Int"] = 9
        elif str(entries[i]['Date'])[5] == '1' and entries[i]['Date'][6] == '0':
            entries[i]["Month-String"] = "October"
            entries[i]["Month-Int"] = 10
        elif str(entries[i]['Date'])[5] == '1' and entries[i]['Date'][6] == '1':
            entries[i]["Month-String"] = "November"
            entries[i]["Month-Int"] = 11
        else:
            entries[i]["Month-String"] = "December"
            entries[i]["Month-Int"] = 12
        
        # get time interval 
        entries[i]["Time Start"] = ((year_num-1) * 12) + entries[i]["Month-Int"]
        entries[i]["Time End"] = total_years * 12
        
    return entries


# # Networks

# In[4]:


# creates an inverse cosine matrix 

def create_cos_matrix(vectors):
    length = len(vectors)
    matrix = np.zeros((length, length))
    row_means =list() 
    for i in range(0,length):
        for j in range(i,length):
            mean = 0
            dist = spatial.distance.cosine(vectors[i], vectors[j])
            cos = abs(1/(1-dist))
            
            #cos = abs(1/(1-spatial.distance.cosine(vectors[i], vectors[j])))
            matrix[i][j] = cos
            matrix[j][i] = cos 
            mean +=cos
        
            if(cos == 1):
                matrix[i][j] = 999
                matrix[j][i] = 999
        mean = mean/length
        row_means.append(mean)
        
    for i in range(0,length):
        for j in range(i,length):
            if  matrix[i][j] < row_means[i]:
                matrix[i][j] = 0
                matrix[j][i] = 0 
                
    return matrix

def create_cos_matrix_pure(vectors):
    length = len(vectors)
    matrix = np.zeros((length, length))
 
    for i in range(0,length):
        for j in range(i,length):
            mean = 0
            dist = spatial.distance.cosine(vectors[i], vectors[j])
            cos = abs(1/(1-dist))
            #cos = abs(1/(1-spatial.distance.cosine(vectors[i], vectors[j])))
            matrix[i][j] = cos
            matrix[j][i] = cos 
                 
    return matrix

def create_cos_matrix_combined(vectors):
    length = len(vectors)
    pure_matrix = np.zeros((length, length))
    modified_matrix = np.zeros((length, length))
    row_means =list() 
    
    for i in range(0,length):
        for j in range(i,length):
            mean = 0
            dist = spatial.distance.cosine(vectors[i], vectors[j])
            cos = abs(1/(1-dist))
            modified_matrix[i][j] = cos
            modified_matrix[j][i] = cos 
            pure_matrix[i][j] = cos
            pure_matrix[j][i] = cos 
            mean += cos
        
            if(cos == 1):
                modified_matrix[i][j] = 999
                modified_matrix[j][i] = 999
        mean = mean/length
        row_means.append(mean)
        
    for i in range(0,length):
        for j in range(i,length):
            if  modified_matrix[i][j] < row_means[i]:
                modified_matrix[i][j] = 0
                modified_matrix[j][i] = 0 
                
    return [pure_matrix, modified_matrix]
    
    

# create a spanning tree from a cosine matrix for exporting to r

def get_spanning_tree(cos_matrix):
    X = sparse.csr_matrix(cos_matrix)
    Tcsr = minimum_spanning_tree(X)
    arr = Tcsr.toarray().astype(float)        
    return arr
                
# create a networkx graph from a cosine matrix 
    
def create_network(cos_matrix):
    X = sparse.csr_matrix(cos_matrix)
    Tcsr = minimum_spanning_tree(X)
    arr = Tcsr.toarray().astype(float)
    G = nx.from_numpy_array(arr, parallel_edges=False, create_using=None)
    return G

    
# convert networkx network to an igraph

def create_igraph(G, entries,subnetwork = False):
    # convert to igraph
    h = ig.Graph.from_networkx(G)
    weights_i = h.es["weight"]
    
    if subnetwork == True:
        return h
    
    spanning_tree = h.spanning_tree(weights=weights_i, return_tree=True)
    start_times = list()
    end_times = list()
    for i in range(0,len(entries)):
        start_times.append(entries[i]['Time Start'])
        end_times.append(entries[i]['Time End'])
        
    spanning_tree.vs["start_time"] = start_times
    spanning_tree.vs["end_time"] = end_times
    
    edge_times = list()
    for edge in spanning_tree.es:
        target_vertex_id = edge.target
        edge_times.append(entries[target_vertex_id]['Time Start'])
    
    spanning_tree.es["start_time"] = edge_times
    spanning_tree.es["end_time"] = end_times

    return spanning_tree
    
    
# write edge attributes to a csv file 

def edge_list_to_csv(I,filename):
    row_list = [["start_time","end_time","source","target",'weight']]
    
    for edge in I.es:
        source = edge.source
        target = edge.target
        cur = [edge['start_time'],edge['end_time'],source,target,edge['weight']]
        row_list.append(cur)
        
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(row_list)
        
# write edge attributes to a csv file 

def node_list_to_csv(I,filename):
    row_list = [["id","start_time","end_time"]]
    for node in I.vs:
        row_list.append([node['_nx_name'],node['start_time'],node['end_time']])
        
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(row_list)


# # Indicator Matrix

# In[1]:


vuln_types = {'Buffer Overflow': ['overflow'], 'Buffer Underflow': ['underflow'], 'Injection': ['injection'], 
              'Broken authentication': ['authentication'], 
              'XSS': ['XSS','scripting'], 'SSRF': ['server'], 'CSRF': ['cross'], 'Null Pointer Dereference': ['pointer'],
              'Out of Bounds': ['bounds'], 'Directory/path Traversal': ['path','directory','traversal'], 
              'Sensitive Data Exposure': ['sensitive'], 'Elevation Priveleges': ['elevation'], 
              'Spoofing': ['spoofing','spoof'], 'Denial of Service': ['denial','service'], 
              'Bypass Restrictions': ['bypass'], 'Broken Access Control': ['access'],
              'Unauthorized Access': ['privileged'],'FTP Issues': ['FTP'],'XML External Entities':['external'],
              'Integer Overflow':['integer'], 'SSRF':['server'],'Improper Initialization':['initialization'],
              'Improper Sanitaization':['sanitization'],'Improper Neutralization':['neutralization'],
             'SSL Isssues':['SSL','sockets'],'Heap Overflow':['heap']}


# In[2]:


len(vuln_types)


# In[5]:


# split vulnerability texts by month from each year

def split_by_month(entries,num_years):
    split = []
    for i in range(0,num_years*12):
        split.append([])
    
    for i in range(0,len(entries)):
        month = entries[i]['Time Start']
        split[month-1].append(entries[i]['Description-Tokenized'])
        
    return split

def split_by_year(entries,file_length):
    split = []
    for i in range(0,len(files)):
        split.append([])
    
    for i in range(0,len(entries)):
        year = entries[i]["Year-Int"]
        split[year-1].append(entries[i]['Description-Tokenized'])
        
    return split


# get column per year of vulnerability presence (0 if present, 1 if not)

def get_col(month): 
    col = []
    for i in range(0,len(vuln_types)):
        col.append(0)
    
    row = 0
    for vuln in month:
        for word in vuln:
            for key,value in vuln_types.items():
                if is_member(word,value):
                    col[row] = 1
                row+=1
            row = 0
    return col


def create_indicator_matrix(entries,num_years):
    months = split_by_month(entries,num_years)
    indic_matrix = np.zeros((len(vuln_types), num_years*12))
    col = 0
    
    for month in months:
        for i in range(0,len(vuln_types)):
            indic_matrix[i][col] = get_col(month)[i]
        col += 1
 
    return indic_matrix 


# # Main Method

# In[6]:


files = ['/CVEDatasSets/allitems-cvrf-year-1999.xml',
        '/CVEDatasSets/allitems-cvrf-year-2000.xml',
        '/CVEDatasSets/allitems-cvrf-year-2001.xml',
        '/CVEDatasSets/allitems-cvrf-year-2002.xml',
        '/CVEDatasSets/allitems-cvrf-year-2003.xml',
        '/CVEDatasSets/allitems-cvrf-year-2004.xml',
         '/CVEDatasSets/allitems-cvrf-year-2005.xml',
         '/CVEDatasSets/allitems-cvrf-year-2006.xml',
         '/CVEDatasSets/allitems-cvrf-year-2007.xml',
        '/CVEDatasSets/allitems-cvrf-year-2008.xml',
         '/CVEDatasSets/allitems-cvrf-year-2009.xml',
        '/CVEDatasSets/allitems-cvrf-year-2010.xml',
        '/CVEDatasSets/allitems-cvrf-year-2011.xml',
        '/CVEDatasSets/allitems-cvrf-year-2012.xml',
        '/CVEDatasSets/allitems-cvrf-year-2013.xml',
        '/CVEDatasSets/allitems-cvrf-year-2014.xml',
        '/CVEDatasSets/allitems-cvrf-year-2015.xml',
        '/CVEDatasSets/allitems-cvrf-year-2016.xml',
        '/CVEDatasSets/allitems-cvrf-year-2017.xml',
         '/CVEDatasSets/allitems-cvrf-year-2018.xml',
        '/CVEDatasSets/allitems-cvrf-year-2019.xml',
        '/CVEDatasSets/allitems-cvrf-year-2020.xml',
        '/CVEDatasSets/allitems-cvrf-year-2021.xml']


# In[7]:


def main(files):
    num_years = len(files)
    file_info = read_files(files)
    entries = file_info[0]
    text = file_info[1]
    indic_matrix = create_indicator_matrix(entries,num_years)
    return indic_matrix


# In[8]:


indic_matrix = main(files)


# In[10]:


row_names = []
for k,v in vuln_types.items():
    row_names.append(k)

# adjust years according to given data set 
months = ['Jan','Feb','Mar','April','May','June','July','Aug','Sept','Oct','Nov','Dec']
years = ['1999','2000','2001','2002','2003','2004','2005','2006','2007','2008','2009',
        '2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021']

col_names = []
month = 0
year = 0
for i in range(0,len(years)*12):
    cur_col = "{month} {year}".format(month = months[month],year = years[year])
    col_names.append(cur_col)
    if(month==11):
        month = 0
        year = year+1
    else:
        month= month+1  


# In[12]:


df = pd.DataFrame(indic_matrix, columns=col_names, index=row_names)


# In[13]:


df.tail()


# In[14]:


savetxt('1999-2021indicator_matrix.csv', indic_matrix, delimiter=',')


# In[15]:


df.to_csv('1999-2021indicator_dataframe.csv', sep=',')


# In[9]:


count = 1
for key,value in vuln_types.items():
    print(count,": ",key)
    count = count + 1 


# In[ ]:




