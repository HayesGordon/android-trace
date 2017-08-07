const chalk = require('chalk');
const co = require('co');

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
  let enumeratedClasses = {}
  let newClassesToHook = [];
  let initialEnum = true;
  let classFilter;
  let agent_api = {};

  /*
  LOCAL FUNCTIONS
  */
  function handleEnumerateClasses(className){
    if(!enumeratedClasses[className]){
      enumeratedClasses[className] = true;
      if (classFilter.test(className)){
        newClassesToHook.push(className);
      }

    }
  }
  function handleEnumerateClassesDone(){
    let message =  " Finished enumerating classes: disovered " + newClassesToHook.length + " classes";
    console.log("\n" + chalk_state(message));
    if(newClassesToHook.length > 0){
      // co(function *() {
      //   yield agent_api.providedClassesHook(newClassesToHook);
      // });
      agent_api.providedClassesHook(newClassesToHook);
    }
    newClassesToHook = [];
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
  function setClassFilter(filterVal){
    classFilter = new RegExp(filterVal);
  }
  function printStateInformation(message){
    if (message.type === "info") {
      console.log("\n " + chalk_state(message.data));
    }
  }
  function handleAgentMessage(message){
    if ("undefined" !== typeof message.payload){
      switch(message.payload.type) {
        case "enumerateClasses":
          handleEnumerateClasses(message.payload.data);
          break;
        case "enumerateClassesDone":
          handleEnumerateClassesDone();
          break;
        case "methodCalled":
          printLineBreak();
          console.log(chalk_data(" CLASS ") + message.payload.data.className);
          console.log(chalk_data(" " + message.payload.data.methodType)+ " " + message.payload.data.methodName);
          console.log(chalk_data(" ARGUMENTS: ") + message.payload.data.args);
          break;
        case "constructorCalled":
          printLineBreak();
          console.log(chalk_dataAlternative(" CONSTRUCTOR ") + message.payload.data.className);
          console.log(chalk_dataAlternative(" ARGUMENT TYPES: ") + message.payload.data.args);
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
    handleAgentMessage: handleAgentMessage,
    printStateInformation: printStateInformation,
    setAgentApi: setAgentApi,
    setClassFilter: setClassFilter
  }

})()

module.exports = {
  handler: handler
}
