FUNCFLOW = '''/**
 * @name Data flow from function parameters to variables
 * @description Tracks data flow from the parameters of a function to variables within the function.
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/data-flow-from-parameters
 */

 import cpp
 import semmle.code.cpp.dataflow.DataFlow
 
 from Function f, Parameter p, Expr sink
 where
   f.getName() = "{funcname}" and
   p.getFunction() = f and
   DataFlow::localFlow(DataFlow::parameterNode(p), DataFlow::exprNode(sink)) and
   sink.getEnclosingFunction() = f
 select sink, "Influenced by", p

'''
 
FUNCCALL = '''/**
 * @name Find function calls to a specific function
 * @description Finds all functions that call a specific function and returns the caller's name, file, line number, and the call expression.
 * @kind problem
 * @problem.severity warning
 * @id cpp/find-function-calls
 */

import cpp

from FunctionCall call, Function target, Function caller, File f, Expr arg, int id
where
   target.getName() = "{funcname}" and
   call.getTarget() = target and
   caller = call.getEnclosingFunction() and
   f = call.getFile() and
   call.getLocation().getStartLine() > 0 and
   arg = call.getArgument(id) and
   id >= 0
select caller, caller.getName(), 
   f.getBaseName(), 
   call.getLocation().getStartLine().toString(),
   call.getTarget().getName(),
   call.getNumberOfArguments(),
   arg
   // call.getEnclosingDeclaration()
   // call.getBasicBlock().toString()
   // order call.getArgument(0).toString()
   //concat(call.getArgument([0..call.getNumberOfArguments()-1]).toString(), "---")
   // concat(call.getArgument(1).toString(), ", ")
   '''

MACROCALL = '''import cpp

from MacroInvocation mi
where exists(int i | mi.getExpandedArgument(i).toString() = "{funcname}")
select mi.getMacroName(), mi.getFile().getAbsolutePath(), mi.getLocation().getStartLine(),
  mi.getLocation().getEndLine()
'''