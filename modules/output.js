const chalk = require('chalk');

/*chalk themes*/
const chalk_error = chalk.bold.red;
const chalk_state = chalk.yellow;
const chalk_info = chalk.blue;
const chalk_data = chalk.green;
const chalk_dataAlternative = chalk.cyan;


function handleMessage(message){
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

function stateInformation(message){
  if (message.type === "info") {
    console.log("\n " + chalk_state(message.data));
  }
}

module.exports = {
  handleMessage: handleMessage,
  stateInformation: stateInformation
};
