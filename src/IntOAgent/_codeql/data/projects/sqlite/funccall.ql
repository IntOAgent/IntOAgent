/**
 * @name Find function calls to a specific function
 * @description Finds all functions that call a specific function and returns the caller's name, file, line number, and the call expression.
 * @kind problem
 * @problem.severity warning
 * @id cpp/find-function-calls
 */

import cpp

from FunctionCall call, Function target, Function caller, File f, Expr arg, int id
where
   target.getName() = "integerValue" and
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
   