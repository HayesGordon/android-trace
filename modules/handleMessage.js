const chalk = require('chalk');
const co = require('co');


/*chalk themes*/
const chalk_error = chalk.bold.red;
const chalk_state = chalk.yellow;
const chalk_info = chalk.blue;
const chalk_infoAlternative = chalk.gray;
const chalk_data = chalk.green;
const chalk_dataAlternative = chalk.cyan;

var enumeratedClasses = [];
var newClasses = [];
var initialEnum = true;

function handleMessage(api,message){
  if ("undefined" !== typeof message.payload){
    if (message.payload.type === "methodCalled"){
      console.log(" ------------------");
      console.log(chalk_data(" CLASS ") + message.payload.data.className);
      console.log(chalk_data(" " + message.payload.data.methodType)+ " " + message.payload.data.methodName);
      console.log(chalk_data(" ARGUMENTS: ") + message.payload.data.args);
    } else if (message.payload.type === "constructorCalled"){
      console.log(" ------------------");
      console.log(chalk_dataAlternative(" CONSTRUCTOR ") + message.payload.data.className);
      console.log(chalk_dataAlternative(" ARGUMENT TYPES: ") + message.payload.data.args);
    }
    else if (message.payload.type === "constructorHooked"){
      console.log(" ------------------");
      console.log(chalk_info(" CONSTRUCTOR ") + message.payload.data.className);
      console.log(chalk_info(" ARGUMENT TYPES: ") + message.payload.data.args);
    }
    else if (message.payload.type === "methodHooked"){
      console.log(" ------------------");
      console.log(chalk_info(" CLASS ") + message.payload.data.className);
      console.log(chalk_info(" " + message.payload.data.methodType)+ " " + message.payload.data.methodName);
      console.log(chalk_info(" ARGUMENT TYPES: ") + message.payload.data.args);
    }
    else if (message.payload.type === "enumerateClasses"){
        handleEnumerateClasses(message);
      } else if (message.payload.type === "enumerateClassesDone"){
        handleEnumerateClassesDone(message.payload.data, api);
      }
    else if (message.payload.type === "info"){
      console.log("\n " + chalk_state(message.payload.data));
    }
    else if (message.payload.type === "errorGeneric"){
      console.log("\n " + chalk_error(message.payload.data));
    }
    else if (message.payload.type === "errorHook"){
      console.log(" ------------------");
      console.log(chalk_error(" CLASS ") + message.payload.data.className);
      console.log(chalk_error(" " + message.payload.data.methodType)+ " " + message.payload.data.methodName);
      console.log(chalk_error(" ARGUMENT TYPES: ") + message.payload.data.args);
    }
  }

}

function stateInformation(message){
  if (message.type === "info") {
    console.log("\n " + chalk_state(message.data));
  }
}

function handleEnumerateClasses(message){
  var className = message.payload.data
  if (!(enumeratedClasses.indexOf(className) > -1)){
    enumeratedClasses.push(className);
    newClasses.push(className)
  }
}

function handleEnumerateClassesDone(message, api){
  var messageNew =  message + ": disovered " + newClasses.length + " classes"
  console.log("\n" + chalk_state(messageNew));
  if(newClasses.length > 0){
    co(function *() {
      yield api.providedClassesHook(newClasses);
    });
  }
  newClasses = [];
}

module.exports = {
  handleMessage: handleMessage,
  stateInformation: stateInformation
};
