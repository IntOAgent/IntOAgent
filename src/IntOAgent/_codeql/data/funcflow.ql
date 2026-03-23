/**
 * @name Data flow from function parameters to variables
 * @description Tracks data flow from the parameters of a function to variables within the function.
 * @kind query
 * @problem.severity warning
 * @id cpp/data-flow-from-parameters
 */

 import cpp
 import semmle.code.cpp.dataflow.DataFlow
 
 from Function f, Parameter p, Expr sink
 where
   // 查找名为 "funcName" 的函数
   f.getName() = "concatwsFunc" and
   // 获取该函数的参数
   p.getFunction() = f and
   // 数据流分析：从参数 p 到 sink
   DataFlow::localFlow(DataFlow::parameterNode(p), DataFlow::exprNode(sink)) and
   // 确保 sink 是函数内部的变量或表达式
   sink.getEnclosingFunction() = f
 select sink, "Influenced by", p

