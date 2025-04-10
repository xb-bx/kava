#+build freebsd,netbsd,openbsd
package shared 
import "core:sys/posix"
import "core:strings"

file_exists :: proc (filepath: string) -> bool {
    cpath := strings.clone_to_cstring(filepath)
    defer delete(cpath)
    stat: posix.stat_t = {}    
    return posix.stat(cpath, &stat) == posix.result.OK
}
