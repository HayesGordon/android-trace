'use strict';

const co = require('co');
const frida = require('frida');
const load = require('frida-load');
const program = require('commander');
const agent_handler = require('./modules/agentHandler');

/*
PARSE COMMAND LINE OPTIONS
*/
function list(val) {
  return val.split(',');
}

//TODO sort out these <n>
program
  .version('1.0.0')
  .option('-U, --usb', 'connect to USB device')
  .option('-H --host <n>','connect to remote frida-server on HOST')
  .option('-n, --package-name <n>', 'android application package name')
  .option('-p, --attach-pid <n>', 'attach to PID', parseInt)
  .option('-F, --filter-class <n>', 'specify regex filter for classes to include in trace. The class path will be included as part of the string to be filtered, ex. "com.test.ClassName"')
  .option('-f, --filter-method <n>', 'specify regex filter for methods to include in trace')
  .option('-E, --exclude-classes <items>', 'comma seperated list of class names to exclude, e.g. -E ClassName1,ClassName2', list, [])
  .option('-e, --exclude-methods <items>', 'comma seperated list of method names to exclude, e.g. -e methodName1,methodName2', list, [])
  .option('-l, --load-classes <n>', 'load classes specified in provided file')
  .option('-d, --discover', 'do not perform any tracing, only enumerate classes at run-time and dump to file - filters/exludes apply')
  // .option('-t, --time', 'specify the time in seconds between each class enumeration call, default is 30 seconds')
  // .option('-o, --out', 'specify output file for enumerated classes, default is "classes.json"')
  .option('-r, --running-processes', 'list running processes')
  .parse(process.argv);


if (!process.argv.slice(2).length) {
    program.outputHelp();
    process.exit(1);
}


let host = "";
let filterClass = "";
let filterMethod = "";
let file_name = "";
if (program.host)
  host = program.host;
if (program.filterClass)
  filterClass = program.filterClass;
if (program.filterMethod)
  filterMethod = program.filterMethod;
if (program.loadClasses)
  file_name = program.loadClasses;


//TODO filter by exact class name
const package_name = program.packageName;
const attachPid = program.attachPid;
const exclude_classes = program.excludeClasses;
const exclude_methods = program.excludeMethods;


/*
PRINT STATE INFORMATION
*/
agent_handler.handler.printStateInformation({ type: 'info', data: 'Package Name: ' + package_name });
agent_handler.handler.printStateInformation({ type: 'info', data: 'Filter: ' + filterClass});
agent_handler.handler.printStateInformation({ type: 'info', data: 'Exclude Classes: ' + exclude_classes});
agent_handler.handler.printStateInformation({ type: 'info', data: 'Exclude Methods: ' + exclude_methods });


/*
INIT AGENT AND AGENTHANDLER
*/
co(function *() {

  /*
    "-U", connect over USB
    "-H", connect over HOST - {ip}:{port}
    else print error message and exit
  */
  let device;
  if (program.usb){
    device = yield frida.getUsbDevice(1);
  } else if (program.host){
    const mgr = frida.getDeviceManager();
    device = yield mgr.addRemoteDevice(host);
  } else {
    console.error("\n Please specify USB '-U' or HOST '-H {ip}:{port}' to connect to a device\n")
    process.exit(1);
  }


  /*
    "-r", print running processes on the device and exit
  */
  if (program.runningProcesses){
    let processes = yield device.enumerateProcesses();
    printRunningProcesses(processes);
    process.exit(1);
  }


  /*
    "-n", attach to provided package name
    "-p", attach to provided pid
    else print error message and exit
  */
  let session;
  if (program.packageName){
    session = yield device.attach(package_name);
  } else if (program.attachPid){
    session = yield device.attach(attachPid);
  } else {
    console.error("\n Missing arguments\n");
    process.exit(1);
  }


  /*create agent script*/
  const scr = yield load(require.resolve('./agent.js'));
  const script = yield session.createScript(scr);


  /*load agent script and get script exported components*/
  yield script.load();
  const agent_api = yield script.getExports();


  /*set agent handler fields*/
  agent_handler.handler.setAgentApi(agent_api);
  agent_handler.handler.setClassFilter(filterClass);


  /*create event listener -> call agent message handler*/
  script.events.listen('message', agent_handler.handler.agentMessageHandler);


  /*set agent fields*/
  yield agent_api.setMethodFilter(filterMethod);
  yield agent_api.setExcludeClassNames(exclude_classes);
  yield agent_api.setExcludeMethodNames(exclude_methods);


  /* 
    "-d", do not perform any tracing, only enumerate classes and dump to file for later use - filters/excludes apply
  */
  if (program.discover){
    agent_handler.handler.setEnumerateOnly();
    agent_handler.handler.printStateInformation({ type: 'info', data: 'Enumerating classes every 30 seconds' });

  }

  /*
    make sure that the user does not specify both "-l" and "-d"
    "-d" only enumerate classes and do not perform tracing
    "-l" only trace the classes in the provided file, without any enumeration
  */
  if (program.discover && program.loadClasses) {
    console.error("\n Can not specify both '-l' and '-d' at the same time\n");
    process.exit(1);
  }
  

  /* 
    "-l", hook classes in provided json file, format -> ["com.test.Class1","com.test.Class2"]
    else enumerate classes
  */
  if (program.loadClasses){
    agent_handler.handler.traceClassesFromFile(file_name);
  } else {
    /*enumerate and hook classes at runtime*/
    yield agent_api.enumerateClasses()
    /*enumerate classes every fixed interval to discover new loaded classes*/
    setInterval(enumClasses, 30000, agent_api);
  }


  /*display message to indicate that the script has finished loading*/
  agent_handler.handler.printStateInformation({ type: "info", data: "Script loaded" });
})
.catch(err => {
  console.error(err);
});


/*function called by setInterval to enumerate classes every fixed interval*/
function enumClasses(agent_api){
  agent_api.enumerateClasses()
}


/*function to pretty print running processes*/
function printRunningProcesses(processes){
  processes.map(function(element){
    console.log(" pid: " + element.pid + " ; " + "name: " + element.name);
  })
}
