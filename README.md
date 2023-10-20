# sgraph

sgraph contains data format, structures and algorithms to work with hierachic graph structures. 
Typically it is suitable for representing software structures.

## Install

`pip install sgraph`

## Contributions

The project is welcoming all contributions.


## Core Ontology

A model, `SGraph` consists of a root `SElement`, which may have children of the same type (as in XML). 
Attribute information can be stored via key-value pairs into them.
The `SElement` objects can be connected together via `SElementAssociation` objects.

### Example model

 nginx model has an nginx root element that represents the main directory.
 Inside it, there is a src element. And inside src, there is core.

 https://github.com/nginx/nginx/tree/master/src
  inside core, there are several elements, e.g. nginx.c and nginx.h
  
   https://github.com/nginx/nginx/blob/master/src/core/nginx.c
  
Because nginx.c contains #include directive to nginx.h, in the model it is 
formulated so that there is a relationship (also called as association) from nginx.c element to nginx.h
 
To make model more explicit, that particular relationship should be annotated with type "inc" to describe
the dependency type. 
 
It is also possible to have other attributes assigned to relationships other than type but typically this is rare.


## XML format

In XML dataformat, minimalism is the goal to make it simple and clean. Integers are used as unique identifiers for the elements. 
In the example case, the nginx.h element is assigned with ID 2 and the relationship that is inside nginx.c refers this way to nginx.h

This integer reference system has been designed to make the data format highly performing even with 10 million element models.

<model version="2.1">
  <elements t="architecture">
  <e n="nginx" >
    <e n="src" >
      <e n="core" >
        <e n="nginx.c" >
          <r r="2" t="inc" />
        </e>
        <e i="2" n="nginx.h" >
        </e>
      </e>
    </e>
  </e>
</elements>
</model>


### Deps data format - line based simple format for easy scripting

In Deps data format (usually a .txt file), the above model can be described minimally this way:

   /nginx/src/core/nginx.c:/nginx/src/core/nginx.h:inc
 
Although this might seem very compelling data format to use, it is not recommended for very 
large models, e.g. 10 million elements.


### Using the API

Creating a simple model:

```
>>> from sgraph import SGraph
>>> from sgraph import SElement
>>> from sgraph import SElementAssociation
>>> x = SGraph(SElement(None, ''))
>>> x
<sgraph.sgraph.SGraph object at 0x7f2efae9ad30>

>>> x.to_deps(fname=None)

>>> e1 = x.createOrGetElementFromPath('/path/to/file.x')
>>> e2 = x.createOrGetElementFromPath('/path/to/file.y')
>>> x.to_deps(fname=None)
/path
/path/to
/path/to/file.x
/path/to/file.y

>>> x.to_xml(fname=None)
<model version="2.1">
  <elements>
  <e n="path" >
    <e n="to" >
      <e n="file.x" >
      </e>
      <e n="file.y" >
      </e>
    </e>
  </e>
</elements>
</model>

>>> ea = SElementAssociation(e1, e2, 'use')
>>> ea.initElems()  # ea is not connected to the model before this call.
>>> x.to_deps(fname=None)
/path/to/file.x:/path/to/file.y:use
/path
/path/to
>>>

>>> x.to_xml(fname=None)
<model version="2.1">
  <elements>
  <e n="path" >
    <e n="to" >
      <e n="file.x" >
        <r r="2" t="use" />
      </e>
      <e i="2" n="file.y" >
      </e>
    </e>
  </e>
 </elements>
</model>

```


## Current utilization
[Softagram](https://github.com/softagram) uses it for building up the information model about the 
analyzed software.
