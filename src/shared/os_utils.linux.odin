//+build linux
package shared 
import "core:os"

file_exists :: proc (filepath: string) -> bool {
    return os.exists(filepath)
}
