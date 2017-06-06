'use strict';

const co = require('co');
const frida = require('frida');
const load = require('frida-load');
const program = require('commander');
const output = require('./modules/handleMessage');


/*parse command line options*/
function list(val) {
  return val.split(',');
}

program
  .version('1.0.0')
  .option('-n, --package-name <n>', 'android application package name')
  .option('-f, --filter <n>', 'specify filter for classes to hook, e.g. part of the package name')
  .option('-E, --exclude-classes <items>', 'comma seperated list of class names to exclude, e.g. -E ClassName1,ClassName2', list, [])
  .option('-e, --exclude-methods <items>', 'comma seperated list of method names to exclude, e.g. -e methodName1,methodName2', list, [])
  .parse(process.argv);

if (!process.argv.slice(2).length) {
    program.outputHelp();
    process.exit(1);
}

const packageName = program.packageName;
let filter = "";
if(program.filter){
  filter = program.filter;
} else {
  filter = packageName;
}
//TODO filter by exact class name
const excludeClasses = program.excludeClasses;
const excludeMethods = program.excludeMethods;
output.stateInformation({ type: 'info', data: 'Package Name: ' + packageName });
output.stateInformation({ type: 'info', data: 'Filter: ' + filter});
output.stateInformation({ type: 'info', data: 'Exclude Classes: ' + excludeClasses});
output.stateInformation({ type: 'info', data: 'Exclude Methods: ' + excludeMethods });


/*load agent*/
co(function *() {
  const scr = yield load(require.resolve('./agent.js'));
  const device = yield frida.getUsbDevice();
  const session = yield device.attach(packageName);
  const script = yield session.createScript(scr);


  yield script.load();
  const api = yield script.getExports();

  // handle messages from the frida agent
  script.events.listen('message', output.handleMessage.bind(this, api));

  /*set agent fields*/
  yield api.setClassFilter(filter);
  yield api.setExcludeClassNames(excludeClasses);
  yield api.setExcludeMethodNames(excludeMethods);

  // yield api.enumerateAndHookClasses();
  yield api.enumerateClasses()

  // enumerateClasses();
  setInterval(dumpClasses, 30000, api);

  output.stateInformation({ type: "info", data: "Script loaded" });
})
.catch(err => {
  console.error(err);
});

function dumpClasses(api){
  api.enumerateClasses()
}
