package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lihongjie0209/passman/internal/backup"
	"github.com/lihongjie0209/passman/internal/catalog"
	"github.com/lihongjie0209/passman/internal/config"
	"github.com/lihongjie0209/passman/internal/daemon"
	"github.com/lihongjie0209/passman/internal/ipc"
	"github.com/lihongjie0209/passman/internal/runner"
	"github.com/lihongjie0209/passman/internal/store"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type App struct {
	version string
	paths   config.Paths
	client  ipc.Client
}

func New(version string) *cobra.Command {
	paths, pathErr := config.Resolve()
	app := &App{version: version, paths: paths, client: ipc.Client{Socket: paths.Socket}}
	root := &cobra.Command{Use: "passman", Short: "Agent-safe local secret broker", SilenceUsage: true, SilenceErrors: true}
	root.PersistentPreRunE = func(*cobra.Command, []string) error { return pathErr }
	root.AddCommand(app.initCmd(), app.unlockCmd(), app.lockCmd(), app.statusCmd(), app.entryCmd(), app.catalogCmd(), app.runCmd(), app.revealCmd(), app.passwdCmd(), app.backupCmd(), app.daemonCmd(), completionCmd(root), versionCmd(version))
	return root
}

func (a *App) initCmd() *cobra.Command {
	return &cobra.Command{Use: "init", Short: "Initialize an encrypted vault", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		pass, err := promptPassword("Master password: ")
		if err != nil {
			return err
		}
		defer clear(pass)
		confirm, err := promptPassword("Confirm master password: ")
		if err != nil {
			return err
		}
		defer clear(confirm)
		if !bytesEqual(pass, confirm) {
			return errors.New("passwords do not match")
		}
		if err := store.New(a.paths.DataDir).Init(pass); err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "vault initialized")
	}}
}

func (a *App) unlockCmd() *cobra.Command {
	var ttl time.Duration
	c := &cobra.Command{Use: "unlock", Short: "Unlock the vault daemon", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if ttl < 0 || ttl > 30*24*time.Hour {
			return errors.New("--ttl must be between 0 and 720h")
		}
		if err := daemon.StartBackground(cmd.Context(), a.paths.Socket); err != nil {
			return err
		}
		pass, err := promptPassword("Master password: ")
		if err != nil {
			return err
		}
		defer clear(pass)
		if _, err := a.client.Call(cmd.Context(), ipc.Request{Op: "unlock", Password: pass, TTLSeconds: int64(ttl / time.Second)}); err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "vault unlocked")
	}}
	c.Flags().DurationVar(&ttl, "ttl", 0, "optional automatic lock timeout")
	return c
}

func (a *App) lockCmd() *cobra.Command {
	return &cobra.Command{Use: "lock", Short: "Lock the vault and stop the daemon", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := a.client.Call(cmd.Context(), ipc.Request{Op: "lock"})
		if err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "vault locked")
	}}
}
func (a *App) statusCmd() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show lock status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := a.client.Call(cmd.Context(), ipc.Request{Op: "status"})
		if err != nil {
			return writeLine(cmd.OutOrStdout(), "locked") //nolint:nilerr // locked is a valid status, including when no daemon exists.
		}
		return writeLine(cmd.OutOrStdout(), "unlocked")
	}}
}

func (a *App) entryCmd() *cobra.Command {
	c := &cobra.Command{Use: "entry", Short: "Manage secret entries"}
	c.AddCommand(a.setCmd(), a.listCmd(), a.removeCmd())
	return c
}

func (a *App) setCmd() *cobra.Command {
	var fromStdin, generate bool
	var file string
	var length int
	c := &cobra.Command{Use: "set <entry>#<field>", Short: "Store a secret without putting it in argv", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		n := 0
		if fromStdin {
			n++
		}
		if file != "" {
			n++
		}
		if generate {
			n++
		}
		if n > 1 {
			return errors.New("choose only one of --stdin, --file, or --generate")
		}
		var value []byte
		var err error
		switch {
		case fromStdin:
			value, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1<<20+1))
		case file != "":
			value, err = os.ReadFile(file) // #nosec G304 -- reading an explicit user-selected secret source is this command's purpose.
		case generate:
			value, err = generateSecret(length)
		default:
			value, err = promptPassword("Secret value: ")
		}
		if err != nil {
			return err
		}
		defer clear(value)
		if len(value) > 1<<20 {
			return errors.New("secret exceeds 1 MiB limit")
		}
		_, err = a.client.Call(cmd.Context(), ipc.Request{Op: "set", Ref: args[0], Value: value})
		if err != nil {
			return err
		}
		if err := catalog.New(a.paths.DataDir).TrackField(args[0], true); err != nil {
			return fmt.Errorf("secret stored but catalog update failed: %w", err)
		}
		return writeLine(cmd.OutOrStdout(), "secret stored")
	}}
	c.Flags().BoolVar(&fromStdin, "stdin", false, "read exact secret bytes from stdin")
	c.Flags().StringVar(&file, "file", "", "read exact secret bytes from file")
	c.Flags().BoolVar(&generate, "generate", false, "generate and store a random base64url secret")
	c.Flags().IntVar(&length, "length", 32, "generated secret length")
	return c
}

func (a *App) listCmd() *cobra.Command {
	var output string
	c := &cobra.Command{Use: "list [entry-prefix]", Short: "List metadata only", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		prefix := ""
		if len(args) > 0 {
			prefix = args[0]
		}
		resp, err := a.client.Call(cmd.Context(), ipc.Request{Op: "list", Prefix: prefix})
		if err != nil {
			return err
		}
		if output == "json" {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetEscapeHTML(false)
			return enc.Encode(resp.Metadata)
		}
		if output != "table" {
			return errors.New("output must be table or json")
		}
		for _, m := range resp.Metadata {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s#%s\t%s\n", m.Entry, m.Field, m.UpdatedAt.Format(time.RFC3339)); err != nil {
				return err
			}
		}
		return nil
	}}
	c.Flags().StringVarP(&output, "output", "o", "table", "table or json")
	return c
}

func (a *App) removeCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{Use: "remove <entry>[#field]", Short: "Remove an entry or field", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !yes {
			return errors.New("refusing removal without --yes")
		}
		_, err := a.client.Call(cmd.Context(), ipc.Request{Op: "remove", Target: args[0]})
		if err != nil {
			return err
		}
		if err := catalog.New(a.paths.DataDir).RemoveTracked(args[0]); err != nil {
			return fmt.Errorf("secret removed but catalog update failed: %w", err)
		}
		return writeLine(cmd.OutOrStdout(), "secret removed")
	}}
	c.Flags().BoolVar(&yes, "yes", false, "confirm removal")
	return c
}

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (a *App) catalogCmd() *cobra.Command {
	c := &cobra.Command{Use: "catalog", Short: "Query unencrypted Agent-readable metadata"}
	c.AddCommand(a.catalogSetCmd(), a.catalogGetCmd(), a.catalogListCmd(), a.catalogSearchCmd(), a.catalogRemoveCmd())
	return c
}

func (a *App) catalogSetCmd() *cobra.Command {
	var item catalog.Item
	c := &cobra.Command{Use: "set <entry>", Short: "Set public metadata; never put secrets here", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		item.ID = args[0]
		if err := catalog.New(a.paths.DataDir).Set(item); err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "public catalog metadata stored")
	}}
	c.Flags().StringVar(&item.Name, "name", "", "public display name")
	c.Flags().StringVar(&item.IP, "ip", "", "public IP address")
	c.Flags().StringVar(&item.URL, "url", "", "public absolute URL without credentials")
	c.Flags().StringVar(&item.Note, "note", "", "public note; must not contain secrets")
	c.Flags().StringSliceVar(&item.Tags, "tags", nil, "comma-separated public tags")
	return c
}

func (a *App) catalogGetCmd() *cobra.Command {
	var output string
	c := &cobra.Command{Use: "get <entry>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		item, err := catalog.New(a.paths.DataDir).Get(args[0])
		if err != nil {
			return err
		}
		return writeCatalog(cmd.OutOrStdout(), []catalog.Item{item}, output)
	}}
	c.Flags().StringVarP(&output, "output", "o", "json", "json or table")
	return c
}

func (a *App) catalogListCmd() *cobra.Command {
	var output string
	c := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		items, err := catalog.New(a.paths.DataDir).List()
		if err != nil {
			return err
		}
		return writeCatalog(cmd.OutOrStdout(), items, output)
	}}
	c.Flags().StringVarP(&output, "output", "o", "json", "json or table")
	return c
}

func (a *App) catalogSearchCmd() *cobra.Command {
	var output string
	c := &cobra.Command{Use: "search <query>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		items, err := catalog.New(a.paths.DataDir).List()
		if err != nil {
			return err
		}
		return writeCatalog(cmd.OutOrStdout(), catalog.Search(items, args[0]), output)
	}}
	c.Flags().StringVarP(&output, "output", "o", "json", "json or table")
	return c
}

func (a *App) catalogRemoveCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{Use: "remove <entry>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !yes {
			return errors.New("refusing removal without --yes")
		}
		if err := catalog.New(a.paths.DataDir).Remove(args[0]); err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "public catalog metadata removed")
	}}
	c.Flags().BoolVar(&yes, "yes", false, "confirm removal")
	return c
}

func writeCatalog(w io.Writer, items []catalog.Item, output string) error {
	if output == "json" {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(items)
	}
	if output != "table" {
		return errors.New("output must be json or table")
	}
	clean := func(v string) string { return strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(v) }
	for _, item := range items {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", item.ID, clean(item.Name), item.IP, clean(item.URL), clean(item.Note), strings.Join(item.Tags, ","), strings.Join(item.SecretFields, ",")); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) runCmd() *cobra.Command {
	var envSpecs, fileSpecs []string
	var stdinRef string
	c := &cobra.Command{Use: "run -- [program] [args...]", Short: "Run a command with injected secrets and redacted output", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		refs := make([]string, 0)
		envRefs := map[string]string{}
		fileRefs := map[string]string{}
		for _, spec := range envSpecs {
			name, ref, err := splitMapping(spec)
			if err != nil || !envNamePattern.MatchString(name) {
				return errors.New("invalid --env mapping")
			}
			envRefs[name] = ref
			refs = append(refs, ref)
		}
		for _, spec := range fileSpecs {
			name, ref, err := splitMapping(spec)
			if err != nil || !fileNamePattern.MatchString(name) {
				return errors.New("invalid --file mapping")
			}
			fileRefs[name] = ref
			refs = append(refs, ref)
		}
		if stdinRef != "" {
			refs = append(refs, stdinRef)
		}
		refs = unique(refs)
		resp, err := a.client.Call(cmd.Context(), ipc.Request{Op: "resolve", Refs: refs})
		if err != nil {
			return err
		}
		defer wipeMap(resp.Values)
		opts := runner.Options{Env: map[string][]byte{}, Files: map[string][]byte{}, Args: args, Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr()}
		for name, ref := range envRefs {
			opts.Env[name] = resp.Values[ref]
		}
		for name, ref := range fileRefs {
			opts.Files[name] = resp.Values[ref]
		}
		if stdinRef != "" {
			opts.Stdin = resp.Values[stdinRef]
		}
		return runner.Run(cmd.Context(), opts)
	}}
	c.Flags().StringArrayVar(&envSpecs, "env", nil, "inject environment variable NAME=entry#field")
	c.Flags().StringArrayVar(&fileSpecs, "file", nil, "inject 0600 file NAME=entry#field and use {file:NAME}")
	c.Flags().StringVar(&stdinRef, "stdin", "", "inject entry#field as child stdin")
	return c
}

func (a *App) revealCmd() *cobra.Command {
	return &cobra.Command{Use: "reveal <entry>#<field>", Short: "Reveal to a real terminal after re-authentication", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil || !term.IsTerminal(int(tty.Fd())) {
			if tty != nil {
				_ = tty.Close()
			}
			return errors.New("reveal requires a controlling TTY and must not be used from an Agent session")
		}
		defer func() { _ = tty.Close() }()
		pass, err := readPassword(tty, "Master password: ")
		if err != nil {
			return err
		}
		defer clear(pass)
		resp, err := a.client.Call(cmd.Context(), ipc.Request{Op: "reveal", Ref: args[0], Password: pass})
		if err != nil {
			return err
		}
		defer clear(resp.Value)
		if _, err = tty.Write(resp.Value); err == nil && !strings.HasSuffix(string(resp.Value), "\n") {
			_, err = tty.Write([]byte("\n"))
		}
		return err
	}}
}

func (a *App) passwdCmd() *cobra.Command {
	return &cobra.Command{Use: "passwd", Short: "Change the master password", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		old, err := promptPassword("Current master password: ")
		if err != nil {
			return err
		}
		defer clear(old)
		next, err := promptPassword("New master password: ")
		if err != nil {
			return err
		}
		defer clear(next)
		confirm, err := promptPassword("Confirm new master password: ")
		if err != nil {
			return err
		}
		defer clear(confirm)
		if !bytesEqual(next, confirm) {
			return errors.New("passwords do not match")
		}
		_, err = a.client.Call(cmd.Context(), ipc.Request{Op: "passwd", Password: old, NewPassword: next})
		if err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "master password changed")
	}}
}

func (a *App) backupCmd() *cobra.Command {
	c := &cobra.Command{Use: "backup", Short: "Create or restore encrypted backups"}
	var output string
	create := &cobra.Command{Use: "create", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if output == "" {
			return errors.New("--output is required")
		}
		resp, err := a.client.Call(cmd.Context(), ipc.Request{Op: "status"})
		if err == nil || resp.Error != "" {
			return errors.New("lock the vault before creating a backup")
		}
		if err := backup.Create(store.New(a.paths.DataDir), output); err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "encrypted backup created")
	}}
	create.Flags().StringVar(&output, "output", "", "new backup file path")
	var input string
	var replace bool
	restore := &cobra.Command{Use: "restore", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if input == "" {
			return errors.New("--input is required")
		}
		resp, err := a.client.Call(cmd.Context(), ipc.Request{Op: "status"})
		if err == nil || resp.Error != "" {
			return errors.New("lock the vault before restoring a backup")
		}
		s := store.New(a.paths.DataDir)
		_, statErr := os.Stat(s.IdentityPath())
		if statErr == nil && !replace {
			return errors.New("vault already exists; use --replace")
		}
		identity, vaultData, catalogData, err := backup.Read(input)
		if err != nil {
			return err
		}
		pass, err := promptPassword("Backup master password: ")
		if err != nil {
			return err
		}
		defer clear(pass)
		if err := s.ValidateCiphertexts(identity, vaultData, pass); err != nil {
			return err
		}
		if statErr == nil {
			rollback := filepath.Join(a.paths.DataDir, "rollback-"+time.Now().UTC().Format("20060102T150405Z")+".pmbak")
			if err := backup.Create(s, rollback); err != nil {
				return fmt.Errorf("creating rollback backup: %w", err)
			}
		}
		if err := s.ReplaceCiphertexts(identity, vaultData); err != nil {
			return err
		}
		if err := catalog.New(a.paths.DataDir).Replace(catalogData); err != nil {
			return fmt.Errorf("vault restored but catalog restore failed: %w", err)
		}
		return writeLine(cmd.OutOrStdout(), "encrypted backup restored")
	}}
	restore.Flags().StringVar(&input, "input", "", "backup file path")
	restore.Flags().BoolVar(&replace, "replace", false, "replace an existing vault after creating a rollback backup")
	c.AddCommand(create, restore)
	return c
}

func (a *App) daemonCmd() *cobra.Command {
	c := &cobra.Command{Use: "daemon", Short: "Manage the local daemon"}
	serve := &cobra.Command{Use: "serve", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return daemon.New(store.New(a.paths.DataDir)).Serve(cmd.Context(), a.paths.Socket)
	}}
	start := &cobra.Command{Use: "start", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := daemon.StartBackground(cmd.Context(), a.paths.Socket); err != nil {
			return err
		}
		return writeLine(cmd.OutOrStdout(), "daemon started")
	}}
	stop := &cobra.Command{Use: "stop", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := a.client.Call(cmd.Context(), ipc.Request{Op: "lock"})
		return err
	}}
	c.AddCommand(start, stop, serve)
	return c
}

func completionCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Args: cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs), ValidArgs: []string{"bash", "zsh", "fish", "powershell"}, RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			return root.GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			return root.GenFishCompletion(cmd.OutOrStdout(), true)
		default:
			return root.GenPowerShellCompletion(cmd.OutOrStdout())
		}
	}}
}
func versionCmd(version string) *cobra.Command {
	return &cobra.Command{Use: "version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return writeLine(cmd.OutOrStdout(), version) }}
}

func promptPassword(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("a controlling TTY is required")
	}
	defer func() { _ = tty.Close() }()
	return readPassword(tty, prompt)
}
func readPassword(tty *os.File, prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return nil, err
	}
	value, err := term.ReadPassword(int(tty.Fd()))
	_, newlineErr := fmt.Fprintln(tty)
	return value, errors.Join(err, newlineErr)
}

func writeLine(w io.Writer, value string) error { _, err := fmt.Fprintln(w, value); return err }
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
func generateSecret(n int) ([]byte, error) {
	if n < 16 || n > 1024 {
		return nil, errors.New("length must be between 16 and 1024")
	}
	raw := make([]byte, (n*3+3)/4)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return []byte(encoded[:n]), nil
}
func splitMapping(s string) (string, string, error) {
	name, ref, ok := strings.Cut(s, "=")
	if !ok || name == "" || ref == "" {
		return "", "", errors.New("expected NAME=reference")
	}
	return name, ref, nil
}
func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func wipeMap(values map[string][]byte) {
	for _, v := range values {
		clear(v)
	}
}
