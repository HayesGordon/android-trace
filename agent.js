"use strict";

let classHandle = {};
let methodFilter;
let excludeClassNames = [];
let excludeMethodNames = [];

rpc.exports = {
  setMethodFilter: function (filter) {
    methodFilter = new RegExp(filter);
  },
  setExcludeClassNames: function(filter) {
    excludeClassNames = filter;
  },
  setExcludeMethodNames: function(filter) {
    excludeMethodNames = filter;
  },
  enumerateClasses: function() {
    startEnumerateClasses();
  },
  providedClassesHook: function(providedClasses) {
    startProvidedClassesHook(providedClasses);
  }
}

function startEnumerateClasses() {
  if (Java.available) {
    Java.perform(function(){
      try{
        Java.enumerateLoadedClasses({
          onMatch: function(classNameToHook) {
            send({ type: "enumerateClasses", data: classNameToHook });
          },
          onComplete: function() {
            send({ type: "enumerateClassesDone"});
          }
        });
      } catch (err) {
        send({ type: "errorGeneric", data: "Java.perform error" });
        console.error(err);
      }
    });
  } else {
    send({ type: "errorGeneric", data: "Java.available error" });
  }
}

function startProvidedClassesHook(providedClasss){
  //TODO performNow or perform?
  Java.performNow(function(){
      providedClasss.map(function(classNameToHook){
        hookClass(classNameToHook);
    });
  });
}


/******CLASS HOOK FUNCTION******/

function hookClass(classNameToHook){
  //TODO implement exclude and do it better - this can be done in the agent handler
  // var shouldHookClass = true;
  // excludeClassNames.map(function(filter){
  //   if (classNameToHook.indexOf(filter) >= 0) {
  //     shouldHookClass = false;
  //   }
  // });
  try {
    classHandle = Java.use(classNameToHook);
  } catch (err) {
    send({ type: "errorGeneric", data: "Java.use error in class: " +
      classNameToHook + " - skipping class" });
    console.error(err);
    return;
  }

  var allPropertyNames = getAllPropertyNames(classHandle);
  var allFunctionNames = getAllFunctionNames(allPropertyNames);

  allFunctionNames.map(function(methodNameToHook){
    if(!methodFilter.test(methodNameToHook)){
      return;
    }
    //TODO do this better - regex or exact method name search
    if (excludeMethodNames.indexOf(methodNameToHook) > -1){
      return;
    }
    try {
      var catchFail = (classHandle.$init.overloads.length > 1);
      hookConstructors(classNameToHook);
    } catch (err) {
      send({ type: "info", data: "No constructor to hook in class: " + classNameToHook });
      console.error(err);
    }
    if (!(classHandle[methodNameToHook].overloads.length > 1)){
      hookMethod(classNameToHook, methodNameToHook);
    } else {
      hookOverloadedMethod(classNameToHook, methodNameToHook);
    }
  });
}


/*
METHOD AND CONSTRUCTOR HOOK FUNCTIONS
*/
function hookConstructors(classNameToHook){
  var constructorMethods = classHandle.$init.overloads;
  for (var i in constructorMethods){
    var argTypes = constructorMethods[i].argumentTypes.map(function(a) {return a.className;});
    try{
      send({
        type: "constructorHooked",
        data: {
          methodType: "CONSTRUCTOR",
          className: classNameToHook,
          args: argTypes
        }
      });

      classHandle.$init.overload.apply(this, argTypes).implementation = function() {

        var args = Array.prototype.slice.call(arguments);
        // send message on hook
        send({
          type: "constructorCalled",
          data: {
            methodType: "CONSTRUCTOR",
            className: classNameToHook,
            args: JSON.stringify(args)
          }
        });

        return this.$init.apply(this, args);
      }
    } catch (err){
      console.error(err);
    }
  }
}

function hookMethod(classNameToHook, methodNameToHook){
  var argTypes = classHandle[methodNameToHook].argumentTypes.map(function(a) {return a.className;});
  try{
    // send message to indicate the method is being hooked
    send({
      type: "methodHooked",
      data: {
        methodType: "METHOD",
        className: classNameToHook,
        methodName: methodNameToHook,
        args: argTypes
      }
    });

    classHandle[methodNameToHook].implementation = function() {
      var args = Array.prototype.slice.call(arguments);
      // send message on hook
      send({
        type: "methodCalled",
        data: {
          methodType: "METHOD",
          className: classNameToHook,
          methodName: methodNameToHook,
          args: JSON.stringify(args)
        }
      });

      return this[methodNameToHook].apply(this, args);
    };
  }catch (err){
    send({
      type: "errorHook",
      data: {
        methodType: "METHOD",
        className: classNameToHook,
        methodName: methodNameToHook,
        args: argTypes
      }
    });
    console.error(err);
  }
}

function hookOverloadedMethod(classNameToHook, methodNameToHook){
  var overloadedMethods = classHandle[methodNameToHook].overloads;
  for (var i in overloadedMethods){
    var argTypes = overloadedMethods[i].argumentTypes.map(function(a) {return a.className;});
    try{
      // send message to indicate the overloaded method is being hooked
      send({
        type: "methodHooked",
        data: {
          methodType: "OVERLOADED METHOD",
          className: classNameToHook,
          methodName: methodNameToHook,
          args: argTypes
        }
      });

      classHandle[methodNameToHook].overload.apply(this, argTypes).implementation = function() {
        var args = Array.prototype.slice.call(arguments);
        // send message on hook
        send({
          type: "methodCalled",
          data: {
            methodType: "OVERLOADED METHOD",
            className: classNameToHook,
            methodName: methodNameToHook,
            args: JSON.stringify(args)
          }
        });

        return this[methodNameToHook].apply(this, args);
      };
    } catch (err){
      send({
        type: "errorHook",
        data: {
          methodType: "OVERLOADED METHOD",
          className: classNameToHook,
          methodName: methodNameToHook,
          args: argTypes
        }
      });
      console.error(err);
    }
  }
}


/*
CUSTOM FUNCTIONS
*/

/*
return all the property names for an object by walking up the prototype chain
enum/nonenum, self/inherited..
*/
function getAllPropertyNames( obj ) {
    var props = [];

    do {
        props= props.concat(Object.getOwnPropertyNames( obj ));
    } while ( obj = Object.getPrototypeOf( obj ) );

    return props;
}

/*cheap hack to only get the function names of the intended class*/
//TODO do it better I guess
function getAllFunctionNames( propertyNames ) {
  var begin_pos = propertyNames.indexOf("$className");
  var end_pos = propertyNames.indexOf("constructor", begin_pos);
  var functionNames = propertyNames.slice(begin_pos+1, end_pos);
  return functionNames.filter(function(funcName){
    if (typeof(classHandle[funcName]) === "function"){
      return funcName;
    }
  });
}
