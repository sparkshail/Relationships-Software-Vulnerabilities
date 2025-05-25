#!/usr/bin/env python
# coding: utf-8

# In[34]:


from lxml import etree
import xml.etree.ElementTree as ET
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import gensim
from gensim.utils import simple_preprocess
import gensim.similarities 
from gensim.models.word2vec import Word2Vec
import igraph as ig
import networkx as nx
import pandas as pd
import numpy as np
from numpy.linalg import norm
from scipy import spatial
from scipy import sparse
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import minimum_spanning_tree
import csv
from numpy import asarray
from numpy import savetxt
import matplotlib.pyplot as plt


# In[76]:


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
        

def is_member(value, iterable):
    for item in iterable:
        if value is item or value == item:
              return True
    return False

def parse_data(file):
    tree = ET.parse(file)
    root = tree.getroot()
    notes = list()
    cve = list()
    pub = list()
    for i in range(5,len(root)):
        try:
            token = word_tokenize(root[i][1][0].text)
            if is_member("REJECT",token) == False:  
                pub.append(root[i][1][1].text)
                cve.append(root[i][2].text)
                notes.append(root[i][1][0].text)
        except:
            continue
    
    vulns_info = [cve,notes,pub]
    return vulns_info
            
def tokenize(text):
    # Tokenize all notes 
    tokenized = list()
    for i in range(0, len(text)):
        filtered = remove_stopwords(word_tokenize(text[i]))
        tokenized.append(filtered)
                         
    return tokenized

def tokenize_single(sentence):
    filtered = remove_stopwords(word_tokenize(sentence))
    tokenized = [word.lower() for word in filtered] 
    return tokenized

def remove_stopwords(text):
    # NLTK stopwords
    stop_words = stopwords.words('english')
    stop_words.append(')')
    stop_words.append('(')
    stop_words.append('.')
    stop_words.append('')
    stop_words.append(',')
    stop_words.append('via')
    stop_words.append('attackers')
    stop_words.append('vulnerability')
    stop_words.append('arbitrary')
    stop_words.append('``')
    stop_words.append('1')
    stop_words.append('2') 
    stop_words.append(':')
    stop_words.append('versions')
    stop_words.append('attacker')
    
    filtered_sentence = [w for w in text if not w.lower() in stop_words]
    #with no lower case conversion
    filtered_sentence = []
 
    for w in text:
        if w not in stop_words:
            filtered_sentence.append(w)
    return filtered_sentence

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
                   'Month-String':"",'Month-Int': 0,"Year":"","Year-Int":0,"Cluster": 0,
                    "Time Start": 0, "Time End": 0}}
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
        entries[i]["Time Start"] = (year_num * 12) - entries[i]["Month-Int"]
        entries[i]["Time End"] = total_years * 12
        
    return entries


# # 1999-2004

# In[36]:


files_1999_2004 = ['/CVEDatasSets/allitems-cvrf-year-1999.xml',
        '/CVEDatasSets/allitems-cvrf-year-2000.xml',
        '/CVEDatasSets/allitems-cvrf-year-2001.xml',
        '/CVEDatasSets/allitems-cvrf-year-2002.xml',
        '/CVEDatasSets/allitems-cvrf-year-2003.xml',
        '/CVEDatasSets/allitems-cvrf-year-2004.xml']
node_data = pd.read_csv('/Community Results/1999-2004Louvain.csv')


# In[37]:


file_info = read_files(files_1999_2004)
entries = file_info[0]


# In[38]:


node_data


# In[39]:


class_sorted = node_data.sort_values('modularity_class')


# In[40]:


classes = class_sorted.modularity_class.unique()


# In[41]:


from nltk.probability import FreqDist


# In[42]:


top_1999=[101,59,61,69,14]
for value in top_1999:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        sent = entries[id]['Description-Tokenized']
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2005-2007

# In[43]:


files_2005 = [ '/CVEDatasSets/allitems-cvrf-year-2005.xml',
        '/CVEDatasSets/allitems-cvrf-year-2006.xml',
        '/CVEDatasSets/allitems-cvrf-year-2007.xml']
node_data = pd.read_csv('/Community Results/2005-2007Louvain.csv')

file_info = read_files(files_2005)
entries = file_info[0]


# In[44]:


node_data


# In[45]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[46]:


top_2005=[11,109,132,2,121]
for value in top_2005:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        sent = entries[id]['Description-Tokenized']
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2008-2010

# In[47]:


files_2008 = [ '/CVEDatasSets/allitems-cvrf-year-2008.xml',
        '/CVEDatasSets/allitems-cvrf-year-2009.xml',
        '/CVEDatasSets/allitems-cvrf-year-2010.xml']
node_data = pd.read_csv('/Community Results/2008-2010Louvain.csv')

file_info = read_files(files_2008)
entries = file_info[0]


# In[48]:


node_data


# In[49]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[50]:


top_2008=[131,97,93,92,25]
for value in top_2008:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        sent = entries[id]['Description-Tokenized']
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2011-2014

# In[51]:


files_2011 = [ '/CVEDatasSets/allitems-cvrf-year-2011.xml',
        '/CVEDatasSets/allitems-cvrf-year-2012.xml',
        '/CVEDatasSets/allitems-cvrf-year-2013.xml',
            '/CVEDatasSets/allitems-cvrf-year-2014.xml' ]
node_data = pd.read_csv('/Community Results/2011-2014Louvain.csv')

file_info = read_files(files_2011)
entries = file_info[0]


# In[52]:


node_data


# In[53]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[56]:


top_2011=[21,166,5,124,0]
for value in top_2011:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['Id']
        try:
            sent = entries[id]['Description-Tokenized']
        except: 
            continue
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2015-2016

# In[57]:


files_2015 = [ '/CVEDatasSets/allitems-cvrf-year-2015.xml',
        '/CVEDatasSets/allitems-cvrf-year-2016.xml']
node_data = pd.read_csv('/Community Results/2015-2016Louvain.csv')

file_info = read_files(files_2015)
entries = file_info[0]


# In[58]:


node_data


# In[59]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[61]:


top_2015=[52,132,94,99,111]
for value in top_2015:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        try:
            sent = entries[id]['Description-Tokenized']
        except: 
            continue
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2017

# In[62]:


files_2017 = [ '/CVEDatasSets/allitems-cvrf-year-2017.xml']
node_data = pd.read_csv('/Community Results/2017Louvain.csv')

file_info = read_files(files_2017)
entries = file_info[0]


# In[63]:


node_data


# In[64]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[65]:


top_2017=[24,10,28,102,49]
for value in top_2017:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        try:
            sent = entries[id]['Description-Tokenized']
        except: 
            continue
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2018

# In[66]:


files_2018 = [ '/CVEDatasSets/allitems-cvrf-year-2018.xml']
node_data = pd.read_csv('/Community Results/2018Louvain.csv')

file_info = read_files(files_2018)
entries = file_info[0]


# In[67]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[69]:


top_2018=[16,47,38,105,31]
for value in top_2018:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        try:
            sent = entries[id]['Description-Tokenized']
        except: 
            continue
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2019

# In[70]:


files_2019 = [ '/CVEDatasSets/allitems-cvrf-year-2019.xml']
node_data = pd.read_csv('/Community Results/2019Louvain.csv')

file_info = read_files(files_2019)
entries = file_info[0]


# In[71]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[72]:


top_2019=[124,105,112,85,99]
for value in top_2019:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        try:
            sent = entries[id]['Description-Tokenized']
        except: 
            continue
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2020

# In[77]:


files_2020 = [ '/CVEDatasSets/allitems-cvrf-year-2020.xml']
node_data = pd.read_csv('/Community Results/2020Louvain.csv')

file_info = read_files(files_2020)
entries = file_info[0]


# In[78]:


class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[79]:


top_2020=[58,36,35,91,143]
for value in top_2020:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['v__nx_name']
        try:
            sent = entries[id]['Description-Tokenized']
        except: 
            continue
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# # 2021

# In[80]:


files_2021 = [ '/CVEDatasSets/allitems-cvrf-year-2021.xml']
node_data = pd.read_csv('/Community Results/2021Louvain.csv')

file_info = read_files(files_2021)
entries = file_info[0]

class_sorted = node_data.sort_values('modularity_class')
classes = class_sorted.modularity_class.unique()


# In[82]:


node_data


# In[83]:


top_2021=[51,122,5,0,6]
for value in top_2021:
    cur_corpus = []
    print("_____________________________________________________________________________________________________")
    cur_class = classes[value]
    print(cur_class)
    cur_nodes = class_sorted.loc[class_sorted['modularity_class'] == cur_class]
    
    for i in range(0,len(cur_nodes)):
        id = cur_nodes.iloc[i]['Id']
        try:
            sent = entries[id]['Description-Tokenized']
        except: 
            continue
        cur_corpus.extend(sent)
    fdist = FreqDist(cur_corpus)
    top_ten = fdist.most_common(10)
    print(top_ten)
    print("______________________________________________________________________________________________________")


# In[ ]:




