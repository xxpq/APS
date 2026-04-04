package ssh

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"aps/endpoint/utils/ssh/radix"
)

type CommandFlags func() (*flag.FlagSet, any)

type CommandCallback func(fs any, a []string, w StringWriter) error

// The "Command" type represents a command in a Go program, including its name, description, help text,
// flags, and callback function.
// @property {string} Name - The Name property represents the name of the command. It is used to
// identify and execute the command when it is called.
// @property {string} ShortDescription - The ShortDescription property is a string that provides a
// brief description or summary of what the command does. It is typically used to display a short
// description of the command in a command-line interface or help menu.
// @property {string} Help - The `Help` property is a string that provides a detailed description or
// instructions for using the command. It is typically displayed when a user requests help or
// information about the command.
// @property {CommandFlags} Flags - The `Flags` property is of type `CommandFlags`. It is used to
// define any flags or options that can be passed to the command. Flags can be used to modify the
// behavior of the command or provide additional information.
// @property {CommandCallback} Callback - The Callback property is a function or method that will be
// executed when the command is invoked. It is responsible for implementing the logic of the command
// and performing any necessary actions.
type Command struct {
	Name             string
	ShortDescription string
	Help             string
	Flags            CommandFlags
	Callback         CommandCallback
}

// The function `execCommand` executes a command by parsing flags, updating arguments, and calling the
// command's callback function.
func execCommand(c *Command, args []string, w StringWriter) error {
	var (
		fl *flag.FlagSet
		fs any
	)

	if c.Flags != nil {
		fl, fs = c.Flags()
		if fl != nil {
			fl.SetOutput(w.GetWriter())
			err := fl.Parse(args)
			if err != nil {
				return err
			}
			args = fl.Args()
		}
	}

	return c.Callback(fs, args, w)
}

// The function "dumpCommands" writes a list of available commands and their descriptions to a
// StringWriter.
func dumpCommands(c *radix.Tree, w StringWriter) {
	err := w.WriteLine("Available commands:")
	if err != nil {
		// TODO: log
		return
	}

	cmds := make([]string, 0)
	for _, l := range allCommands(c) {
		cmds = append(cmds, fmt.Sprintf("%s - %s", l.Name, l.ShortDescription))
	}

	sort.Strings(cmds)
	w.Write(strings.Join(cmds, "\n") + "\n\n")
}

// The function `lookupCommand` takes a radix tree and a string command, and returns the corresponding
// command object if it exists in the tree.
func lookupCommand(c *radix.Tree, sCmd string) (*Command, error) {
	cmd, ok := c.Get(sCmd)
	if !ok {
		return nil, nil
	}

	command, ok := cmd.(*Command)
	if !ok {
		return nil, errors.New("failed to cast command")
	}

	return command, nil
}

// The function "allCommands" returns a list of all commands stored in a radix tree.
func allCommands(c *radix.Tree) []*Command {
	cmds := make([]*Command, 0)
	c.WalkPrefix("", func(found string, v any) bool {
		cmd, ok := v.(*Command)
		if ok {
			cmds = append(cmds, cmd)
		}
		return false
	})
	return cmds
}

// The `helpCallback` function is used to display information about available commands and their usage.
func helpCallback(commands *radix.Tree, a []string, w StringWriter) error {
	if len(a) == 0 {
		dumpCommands(commands, w)
		return nil
	}

	cmd, err := lookupCommand(commands, a[0])
	if err != nil {
		// TODO: handle error
		// TODO: message the user
		return err
	}

	if cmd != nil {
		err = w.WriteLine(fmt.Sprintf("%s - %s", cmd.Name, cmd.ShortDescription))
		if err != nil {
			return err
		}

		if cmd.Help != "" {
			err = w.WriteLine(fmt.Sprintf("  %s", cmd.Help))
			if err != nil {
				return err
			}
		}

		if cmd.Flags != nil {
			fs, _ := cmd.Flags()
			if fs != nil {
				fs.SetOutput(w.GetWriter())
				fs.PrintDefaults()
			}
		}

		return nil
	}

	err = w.WriteLine("Command not available " + a[0])
	if err != nil {
		return err
	}

	return nil
}
