# Dummy Enforcer Plugin

This is a dummy plugin just to demonstrate the Go native plugin loading mechanism.
Dynamic loading of plugins using the Golang `plugins` is currently only supported
Go +1.8 and Linux systems.

In order to compile the plugin, it must be built as follows:

```bash
go build -buildmode=plugin -o dummy.so
```

The plugin can be loaded into a PADME Enforcer by using a `NativePluginLoader`
configured to use the plugin directory that contains the compiled file.

## Example

Build the `dummy` plugin as follows:

```bash
go build -buildmode=plugin -o dummy.so

# Copy the plugin to the PADME plugins directory
mkdir -p /opt/padme/plugins
cp dummy.so /opt/padme/plugins
```

Then you can dynamically load it in your program as follows:

```go
package main

import (
        "fmt"

        "github.com/padmeio/padme/enforcer/plugins/native"
)

func main() {
        // Initialize the plugin loader
	loader := &native.PluginLoader{
		PluginDir: "/opt/padme/plugins",
	}

	// Load the 'Dummy' exported variable from
	// the '/opt/padme/plugins/dummy.so' plugin file
	plugin, err := loader.Load("dummy")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Loaded plugin: %v\n", plugin.ID())

	// Apply and remove some policies
	plugin.Apply("policy", []byte("Policy plugin data"))
	plugin.Remove("policy")
}
```
