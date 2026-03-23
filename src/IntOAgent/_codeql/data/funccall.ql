/**
 * @name Find function calls to a specific function
 * @description Finds all functions that call a specific function and returns the caller's name, file, line number, and the call expression.
 * @kind problem
 * @problem.severity warning
 * @id cpp/find-function-calls
 */

import cpp

// 查找调用目标函数的函数
from FunctionCall call, Function target, Function caller, File f, Expr arg, int id
where
   // 目标函数的名称匹配
   target.getName() = "concatwsFunc" and
   // 调用目标函数的函数调用
   call.getTarget() = target and
   // 获取调用者函数
   caller = call.getEnclosingFunction() and
   // 获取调用所在的文件
   f = call.getFile() and
   // 获取调用语句的内容
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
   