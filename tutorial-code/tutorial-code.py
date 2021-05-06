from sgraph.modelapi import ModelApi

m = ModelApi(filepath='sample-models/k9_opensource_email_app_model.xml')
elements = m.getElementsByName('markAsContacted')

for element in elements:
    print(element.name, element.type, element.getPath())

createContactFunc = elements[0]

# Which functions are called by it?
print ('Called functions')

calledFunctions = m.getCalledFunctions(createContactFunc)
for c in calledFunctions:
    print(c.name, c.type, c.getPath())

# Which functions are calling it?
print('Functions that are calling it..')

callingFunctions = m.getCallingFunctions(createContactFunc)
for c in callingFunctions:
    print(c.name, c.type, c.getPath())
