package documents

import (
	"cmp"
	"container/heap"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"golang.org/x/sys/unix"
	"golang.org/x/text/cases"
)

type Item struct {
	Name     string  `json:"name"`
	Path     string  `json:"path"`
	Type     string  `json:"type"`
	Size     *int64  `json:"size"`
	Modified float64 `json:"modified"`
}

type Page struct {
	SourceID  string  `json:"sourceId"`
	Path      string  `json:"path"`
	Items     []Item  `json:"items"`
	NextAfter *string `json:"nextAfter"`
}

func (service Service) BrowseSources(ctx context.Context, identity directory.Identity) ([]Source, error) {
	allowed, err := service.allowedSources(ctx, identity, true)
	if err != nil {
		return nil, err
	}

	sources := make([]Source, 0, len(allowed))
	for _, source := range allowed {
		fd, _, err := openDirectory(source.root, nil, source.owner)
		if err != nil {
			continue
		}
		fd.Close()
		sources = append(sources, source)
	}

	fold := cases.Fold()
	slices.SortFunc(sources, func(a, b Source) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(fold.String(a.Label), fold.String(b.Label)), cmp.Compare(a.ID, b.ID))
	})
	return sources, nil
}

func (service Service) BrowseDirectory(ctx context.Context, identity directory.Identity, sourceID, relative, after string, limit int) (Page, error) {
	if limit < 1 || limit > 200 || utf8.RuneCountInString(after) > 255 {
		return Page{}, errors.New("Ungültiger Seitenzeiger oder Seitenumfang")
	}
	allowed, err := service.allowedSources(ctx, identity, true)
	if err != nil {
		return Page{}, err
	}
	source, ok := allowed[sourceID]
	if !ok {
		return Page{}, os.ErrNotExist
	}

	parts, err := pathParts(relative)
	if err != nil {
		return Page{}, err
	}
	dir, rootStat, err := openDirectory(source.root, parts, source.owner)
	if err != nil {
		return Page{}, err
	}
	defer dir.Close()

	items := make(itemHeap, 0, limit+1)
	for ctx.Err() == nil {
		names, err := dir.Readdirnames(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return Page{}, err
		}
		for _, name := range names {
			if name <= after || name == ".trash" || excludedName(name) || !utf8.ValidString(name) ||
				(len(items) == limit+1 && name >= items[0].Name) {
				continue
			}
			item, visible := directoryItem(int(dir.Fd()), rootStat, source, relative, name)
			if !visible {
				continue
			}
			if len(items) == limit+1 {
				items[0] = item
				heap.Fix(&items, 0)
			} else {
				heap.Push(&items, item)
			}
		}
		if errors.Is(err, io.EOF) || len(names) == 0 {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}

	slices.SortFunc(items, func(a, b Item) int { return strings.Compare(a.Name, b.Name) })
	page := Page{SourceID: sourceID, Path: relative, Items: []Item(items)}
	if len(items) > limit {
		page.Items = page.Items[:limit]
		page.NextAfter = &page.Items[limit-1].Name
	}
	return page, nil
}

func directoryItem(fd int, rootStat stat, source Source, relative, name string) (Item, bool) {
	var info unix.Stat_t
	if err := unix.Fstatat(fd, name, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil || info.Dev != rootStat.Dev {
		return Item{}, false
	}
	if rootStat.mountID != 0 {
		var extended unix.Statx_t
		err := unix.Statx(fd, name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID, &extended)
		if err == nil && extended.Mask&unix.STATX_MNT_ID != 0 && extended.Mnt_id != rootStat.mountID {
			return Item{}, false
		}
	}

	path := name
	if relative != "" {
		path = relative + "/" + name
	}
	modified := float64(info.Mtim.Sec) + float64(info.Mtim.Nsec)/1e9
	item := Item{Name: name, Path: path, Modified: modified}
	switch info.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		item.Type = "directory"
		return item, owned(info.Mode, info.Uid, source.owner, 0o500)
	case unix.S_IFREG:
		item.Type = "file"
		item.Size = &info.Size
		return item, owned(info.Mode, info.Uid, source.owner, 0o400)
	default:
		return Item{}, false
	}
}

func (service Service) DownloadPath(ctx context.Context, identity directory.Identity, sourceID, relative string) (*os.File, error) {
	allowed, err := service.allowedSources(ctx, identity, true)
	if err != nil {
		return nil, err
	}
	source, ok := allowed[sourceID]
	if !ok {
		return nil, os.ErrNotExist
	}

	file, _, err := openFile(source.root, relative, source.owner)
	return file, err
}

type itemHeap []Item

func (items itemHeap) Len() int           { return len(items) }
func (items itemHeap) Less(i, j int) bool { return items[i].Name > items[j].Name }
func (items itemHeap) Swap(i, j int)      { items[i], items[j] = items[j], items[i] }
func (items *itemHeap) Push(item any)     { *items = append(*items, item.(Item)) }
func (items *itemHeap) Pop() any {
	last := len(*items) - 1
	item := (*items)[last]
	*items = (*items)[:last]
	return item
}
