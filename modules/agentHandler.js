const chalk = require('chalk');
const co = require('co');
const fs = require('fs');

handler = (function(){

  /*
  CHALK LOCAL VARIABLES
  */
  const chalk_error = chalk.bold.red;
  const chalk_state = chalk.yellow;
  const chalk_info = chalk.blue;
  const chalk_infoAlternative = chalk.gray;
  const chalk_data = chalk.green;
  const chalk_dataAlternative = chalk.cyan;

  /*
  LOCAL VARIABLES
  */
  let agent_api = {};
  let enumerated_classes = {}
  let classes_that_match_filter = []
  let new_classes_to_hook = [];
  let enumerate_only = false;
  let class_exclude_set = false;
  let class_filter_include;
  let class_filter_exclude;

  /*
  LOCAL FUNCTIONS
  */

  function classDiscovered(class_name){
    var test = "/^(?!.*foobar)/";
    if(!enumerated_classes[class_name]){
      enumerated_classes[class_name] = true; // object for searching
      if (filterClass(class_name)) {
        classes_that_match_filter.push(class_name); // array for dumping to discovered classes file
        new_classes_to_hook.push(class_name); // new classes discovered that need to be hooked when enumerate classes is finished
      }
    }
  }

  function outputClassesToFile(){
    fs.writeFile('./classes.json', JSON.stringify(classes_that_match_filter),
      function (err) {
          if (err) {
              console.error(err);
          }
      }
    );
  }

  /*filter class name by user supplied regex - exclude/include*/
  function filterClass(class_name){
    return ((!class_exclude_set || !class_filter_exclude.test(class_name)) && class_filter_include.test(class_name))
  }

  function printLineBreak(){
    console.log(" --------------------------------------------------------------");
  }

  /*
  PUBLIC FUNCTIONS
  */

  function setAgentApi(api){
    agent_api = api;
  }

  function setClassFilter(filter_val){
    class_filter_include = new RegExp(filter_val);
  }

  function setClassExclude(exclude_val){
    //TODO below is a negative look-ahead - Test out the current regex exlcudes method, else revert to below
    // let pattern = "";
    // if (exclude_val){
    //   pattern = "^(?!" + exclude_val + ")"
    // }
    // class_filter_exclude = new RegExp(pattern);
    if (exclude_val)
      class_exclude_set = true;
    class_filter_exclude = new RegExp(exclude_val);
  }

  function setEnumerateOnly() {
    enumerate_only = true;
  }

  function printStateInformation(message){
    if (message.type === "info") {
      console.log("\n " + chalk_state(message.data));
    }
  }

  function traceClassesFromFile(file){
    fs.readFile(file, 'utf8', function (err, data) {
      if (err)
        throw err;
      let classes_from_file = JSON.parse(data);
      let classes_to_hook = classes_from_file.filter(filterClass);
      let message =  " Finished loading classes from file: hooking " + classes_to_hook.length + " classes";
      console.log("\n" + chalk_state(message));
      if (classes_to_hook.length)
        agent_api.providedClassesHook(classes_to_hook);
    });
  }

  function enumerateClassesDone(){
    let message =  " Finished enumerating classes: discovered " + new_classes_to_hook.length + " classes";
    console.log("\n" + chalk_state(message));
    /*if new classes to be hooked are discovered, and the user is performing tracing*/
    if(new_classes_to_hook.length > 0 && !enumerate_only){
      agent_api.providedClassesHook(new_classes_to_hook)
        .then((data) => console.log(chalk_state("\n Finished hooking the discovered methods")))
        .catch((err) => {
          console.log(err);
          console.log(chalk_state("\nThis is a 'Frida' issue (not 'android-trace'). If you see this error it would be a good idea to apply an exclude filter for this specific class and try again.\n"));
        });
    }

    new_classes_to_hook = []; // clear new_classes_to_hook after the classes have been hooked
    outputClassesToFile(); // output all hooked classes to a file
  }

  function agentMessageHandler(message){
    if ("undefined" !== typeof message.payload){
      switch(message.payload.type) {
        case "class_discovered":
          classDiscovered(message.payload.data);
          break;
        case "methodCalled":
          printLineBreak();
          console.log(chalk_data(" CLASS ") + message.payload.data.className);
          console.log(chalk_data(" " + message.payload.data.methodType)+ " " + message.payload.data.methodName);
          // console.log(chalk_data(" ARGUMENT TYPES: ") + message.payload.data.argTypes);
          console.log(chalk_data(" ARGUMENTS: ") + message.payload.data.args);
          console.log(chalk_data(" RETURN: ") + message.payload.data.ret);
          break;
        case "constructorCalled":
          printLineBreak();
          console.log(chalk_dataAlternative(" CONSTRUCTOR ") + message.payload.data.className);
          console.log(chalk_dataAlternative(" ARGUMENT TYPES: ") + message.payload.data.argTypes);
          console.log(chalk_dataAlternative(" ARGUMENTS: ") + message.payload.data.args);
          break;
        case "constructorHooked":
          printLineBreak();
          console.log(chalk_info(" CONSTRUCTOR ") + message.payload.data.className);
          console.log(chalk_info(" ARGUMENT TYPES: ") + message.payload.data.args);
          break;
        case "methodHooked":
          printLineBreak();
          console.log(chalk_info(" CLASS ") + message.payload.data.className);
          console.log(chalk_info(" " + message.payload.data.methodType)+ " " + message.payload.data.methodName);
          console.log(chalk_info(" ARGUMENT TYPES: ") + message.payload.data.args);
          break;
        case "errorHook":
          printLineBreak();
          console.log(chalk_error(" CLASS ") + message.payload.data.className);
          console.log(chalk_error(" " + message.payload.data.methodType)+ " " + message.payload.data.methodName);
          console.log(chalk_error(" ARGUMENT TYPES: ") + message.payload.data.args);
          break;
        case "info":
          printLineBreak();
          console.log("\n " + chalk_state(message.payload.data));
          break;
        case "errorGeneric":
        printLineBreak();
          console.log("\n " + chalk_state(message.payload.data));
          break;
      }
    }
  }

  /*
  RETURN OBJECTS
  */

  return {
    setAgentApi,
    setClassFilter,
    setClassExclude,
    setEnumerateOnly,
    agentMessageHandler,
    traceClassesFromFile,
    enumerateClassesDone,
    printStateInformation
  }

})()

module.exports = {
  handler: handler
}
