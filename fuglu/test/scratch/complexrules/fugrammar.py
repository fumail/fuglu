# Uncomment the line below for readline support on interactive terminal
# import readline  
import re
from pyparsing import Word, alphas, ParseException, Literal, CaselessLiteral \
, Combine, Optional, nums, Or, Forward, ZeroOrMore, StringEnd, alphanums
import math

# Debugging flag can be set to either "debug_flag=True" or "debug_flag=False"
debug_flag=False

exprStack = []
varStack  = []
variables = {}

def pushFirst( str, loc, toks ):
    exprStack.append( toks[0] )

def assignVar( str, loc, toks ):
    varStack.append( toks[0] )

# define grammar
point = Literal('.')
plusorminus = Literal('+') | Literal('-')
number = Word(nums) 
integer = Combine( Optional(plusorminus) + number )
floatnumber = Combine( integer +
                       Optional( point + Optional(number) ) 
                     )

ident = Word(alphas,alphanums + '_') 

equal  = Literal( "==" )
notequal = Literal( "!=" )
regex = Literal("~=")

lpar  = Literal( "(" ).suppress()
rpar  = Literal( ")" ).suppress()
addop  = plus | minus
assign = Literal( "=" )

expr = Forward()
atom = ( (floatnumber | integer | ident ).setParseAction(pushFirst) | 
         ( lpar + expr.suppress() + rpar )
       )

        
term = factor + ZeroOrMore( ( multop + factor ).setParseAction( pushFirst ) )
expr << term + ZeroOrMore( ( addop + term ).setParseAction( pushFirst ) )
bnf = Optional((ident + assign).setParseAction(assignVar)) + expr

pattern =  bnf + StringEnd()

# map operator symbols to corresponding arithmetic operations
opn = { "==" : ( lambda a,b: a == b ),
 }

# Recursive function that evaluates the stack
def evaluateStack( s ):
  op = s.pop()
  if op in "+-*/^":
    op2 = evaluateStack( s )
    op1 = evaluateStack( s )
    return opn[op]( op1, op2 )
  elif op == "PI":
    return math.pi
  elif op == "E":
    return math.e
  elif re.search('^[a-zA-Z][a-zA-Z0-9_]*$',op):
    if variables.has_key(op):
      return variables[op]
    else:
      return 0
  elif re.search('^[-+]?[0-9]+$',op):
    return long( op )
  else:
    return float( op )

if __name__ == '__main__':
  # input_string
  input_string=''
  
  # Display instructions on how to quit the program
  print "Type in the string to be parse or 'quit' to exit the program"
  input_string = raw_input("> ")
  
  while input_string != 'quit':
    # Start with a blank exprStack and a blank varStack
    exprStack = []
    varStack  = []
  
    if input_string != '':
      # try parsing the input string
      try:
        L=pattern.parseString( input_string )
      except ParseException,err:
        L=['Parse Failure',input_string]
      
      # show result of parsing the input string
      if debug_flag: print input_string, "->", L
      if len(L)==0 or L[0] != 'Parse Failure':
        if debug_flag: print "exprStack=", exprStack
  
        # calculate result , store a copy in ans , display the result to user
        result=evaluateStack(exprStack)
        variables['ans']=result
        print result
  
        # Assign result to a variable if required
        if debug_flag: print "var=",varStack
        if len(varStack)==1:
          variables[varStack.pop()]=result
        if debug_flag: print "variables=",variables
      else:
        print 'Parse Failure'
        print err.line
        print " "*(err.column-1) + "^"
        print err
  
    # obtain new input string
    input_string = raw_input("> ")
  
  # if user type 'quit' then say goodbye
  print "Good bye!"


