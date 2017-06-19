'use strict';

const co = require('co');
const frida = require('frida');
const load = require('frida-load');
const program = require('commander');
const output = require('./modules/handleMessage');
const fs = require('fs');

/*parse command line options*/
function list(val) {
  return val.split(',');
}

program
  .version('1.0.0')
  .option('-n, --package-name <n>', 'android application package name')
  .option('-p, --attach-pid <n>', 'attach to PID', parseInt)
  .option('-s, --spawn <n>, package name to spawn')
  .option('-f, --filter <n>', 'specify filter for classes to hook, e.g. part of the package name')
  .option('-E, --exclude-classes <items>', 'comma seperated list of class names to exclude, e.g. -E ClassName1,ClassName2', list, [])
  .option('-e, --exclude-methods <items>', 'comma seperated list of method names to exclude, e.g. -e methodName1,methodName2', list, [])
  .option('-l, --load-classes <items>', 'specify the file name containing a list of classes')
  .option('-t, --time <items>', 'specify the time in seconds between each enumerate loaded classes call', parseInt)
  .parse(process.argv);

if (!process.argv.slice(2).length) {
    program.outputHelp();
    process.exit(1);
}

const packageName = program.packageName;
const attachPid = program.attachPid;
const spawn = program.spawn;
let filter = "";
if(program.filter){
  filter = program.filter;
} else if (program.spawn) {
  filter = spawn;
} else {
  filter = packageName;
}
//TODO filter by exact class name
const excludeClasses = program.excludeClasses;
const excludeMethods = program.excludeMethods;
const fileName = program.loadClasses;
const time = 10000;
if (program.time){
  const time = program.time * 100;
}
output.stateInformation({ type: 'info', data: 'Package Name: ' + packageName });
output.stateInformation({ type: 'info', data: 'PID: ' + attachPid });
output.stateInformation({ type: 'info', data: 'Filter: ' + filter});
output.stateInformation({ type: 'info', data: 'Exclude Classes: ' + excludeClasses});
output.stateInformation({ type: 'info', data: 'Exclude Methods: ' + excludeMethods });
output.stateInformation({ type: 'info', data: 'File Name to load: ' + fileName });


/*load agent*/
co(function *() {
  const scr = yield load(require.resolve('./agent.js'));
  const device = yield frida.getUsbDevice();
  let session = null;
  if (program.spawn){
    const pid = yield device.spawn([spawn]);
    session = yield device.attach(pid);
  } else if (program.attachPid){
    session = yield device.attach(attachPid);
  } else {
    session = yield device.attach(packageName);
  }

  const script = yield session.createScript(scr);

  yield script.load();
  const api = yield script.getExports();

  // handle messages from the frida agent
  script.events.listen('message', output.handleMessage.bind(this, api));

  /*set agent fields*/
  yield api.setClassFilter(filter);
  yield api.setExcludeClassNames(excludeClasses);
  yield api.setExcludeMethodNames(excludeMethods);

  if (program.spawn){
    yield device.resume(spawn);
  }

  if (program.loadClasses){
    let classesFromFile = JSON.parse(fs.readFileSync('classes.json', 'utf8'));
    yield api.providedClassesHook(classesFromFile);
  } else {
    yield api.enumerateClasses()
    setInterval(dumpClasses, 10000, api);

  }
  output.stateInformation({ type: "info", data: "Script loaded" });
})
.catch(err => {
  console.error(err);
});

function dumpClasses(api){
  api.enumerateClasses()
}

// function getAllPropertyNames( obj ) {
//     var props = [];
//
//     do {
//         props= props.concat(Object.getOwnPropertyNames( obj ));
//     } while ( obj = Object.getPrototypeOf( obj ) );
//
//     return props;
// }
