# Frida Tips
The documentation is so limited. A compilation of things I found on StackOverflow and don't want to have to search it up again.

### Bypass root check
```js
setTimeout(function() { // avoid java.lang.ClassNotFoundException

  Java.perform(function() {

    // Root detection bypass example

    var hook = Java.use("com.target.utils.RootCheck");
    console.log("info: hooking target class");

    hook.isRooted.overload().implementation = function() {
      console.log("info: entered target method");
      
      // obtain old retval
      var retval = this.isRooted.overload().call(this);
      console.log("old ret value: " + retval);

      // set new retval
      var retnew = false;
      console.log("new ret value: " + retnew);
      return retnew;
    }

  });   

}, 0);
```

### Create instance of class and call its methods
```js
Java.perform(function(){
  a=Java.use("com.AppSecLabs.AppName.MainActivity");
  Java.scheduleOnMainThread(function(){
    b=a.$new();
    console.log(b.myMethod1("a","b"));
    console.log(b.myMethod2("f"));
  })
})
```

### Enumerate all loaded classes
```js
// enumerate all Java classes
function enumAllClasses()
{
  var allClasses = [];
  var classes = Java.enumerateLoadedClassesSync();

  classes.forEach(function(aClass) {
    try {
      var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
    }
    catch(err) {} // avoid TypeError: cannot read property 1 of null
    allClasses.push(className);
  });

  return allClasses;
}

setTimeout(function() { // avoid java.lang.ClassNotFoundException

  Java.perform(function() {

    // enumerate all classes
    var a = enumAllClasses();
    a.forEach(function(s) { 
      console.log(s); 
    });
  });
}, 0);
```

### Enumerate classes that matches pattern
```js
// find all Java classes that match a pattern
function findClasses(pattern)
{
  var allClasses = enumAllClasses();
  var foundClasses = [];

  allClasses.forEach(function(aClass) {
    try {
      if (aClass.match(pattern)) {
        foundClasses.push(aClass);
      }
    }
    catch(err) {} // avoid TypeError: cannot read property 'match' of undefined
  });

  return foundClasses;
}

setTimeout(function() { // avoid java.lang.ClassNotFoundException

  Java.perform(function() {
    // find classes that match a pattern
    var a = findClasses(/password/i);
    a.forEach(function(s) { 
      console.log(s); 
    });
      });
}, 0);
```

### Enumerate all methods of a class
```js
// enumerate all methods declared in a Java class
function enumMethods(targetClass)
{
  var hook = Java.use(targetClass);
  var ownMethods = hook.class.getDeclaredMethods();
  hook.$dispose;

  return ownMethods;
}

setTimeout(function() { // avoid java.lang.ClassNotFoundException
  Java.perform(function() {
    // enumerate all methods in a class
    var a = enumMethods("com.target.app.PasswordManager")
    a.forEach(function(s) { 
      console.log(s); 
    });
  });
}, 0);
```

### Get object member
```js
Java.perform(function(){
  person = Java.use("com.simon.persontest.Person")
  main = Java.use("com.simon.persontest.MainActivity")
  field = Java.use("java.lang.reflect.Field")
  clazz = Java.use("java.lang.Class")
  main.test.implementation = function(p){
    var tmp = p
    console.log(tmp)
    var field_name = Java.cast(tmp.getClass(),clazz).getDeclaredField("name")
    field_name.setAccessible(true)
    field_name.set(tmp,"H4oK3")
    return this.test(p)
  }
});
```

### Print call stack
```js
setImmediate(function() {
  Java.perform(function () {
    var Activity = Java.use("com.package.MyClass");
    Activity.getUpdates.overload('boolean', 'java.lang.String', 'java.lang.String').implementation  = function (v1, v2, v3) {
      Java.perform(function() {
          console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
      });
    };
  });
})
```

### Get class of object
```js
Java.vm.getEnv().getObjectClassName(obj.$handle)
```
