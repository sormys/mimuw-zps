package tui

import (
	"fmt"
	"mimuw_zps/src/handler"
	"mimuw_zps/src/message_manager"
	"mimuw_zps/src/networking"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// My implementtion was guided by the official documentation
// https://github.com/charmbracelet/bubbletea

type state string

const (
	CHOOSE_USER state = "user"
	USER_INFO   state = "info"
	FOLDER      state = "folder"
)

type model struct {
	state        state
	cursor       int
	users        []networking.Peer
	selectedUser networking.Peer
	tuiSender    chan<- message_manager.TuiMessage
	tuiReceiver  <-chan message_manager.TuiMessage

	infoOutside  string
	errorOutside string
	VisibleItems []VisibleItem
	root         message_manager.TUIFolder
	initialState bool
}

// Useful for displaying a hierarchial file tree structure
type VisibleItem struct {
	Path     string
	Name     string
	isFolder bool
	Depth    int
	Hash     handler.Hash
}

// Marks a user as connected. We dont have a lots of users that's why
// linear complexity is acceptable
func (m *model) updateUserState(user networking.Peer) {
	for i, u := range m.users {
		if u.Name == user.Name {
			m.users[i].Stage = networking.CONNECT
			break
		}
	}
}

func showMyLevel(folder message_manager.TUIFolder, depth int, tmp *[]VisibleItem) {
	*tmp = append(*tmp, VisibleItem{
		Path:     folder.Path,
		Name:     folder.Name,
		isFolder: true,
		Hash:     folder.Hash,
		Depth:    depth,
	})

	if folder.Expanded {
		for i := 0; i < len(folder.Files); i++ {
			file := folder.Files[i]
			*tmp = append(*tmp, VisibleItem{
				Path:     folder.Path + "/" + file.Name,
				Name:     file.Name,
				isFolder: false,
				Hash:     file.Hash,
				Depth:    depth + 1,
			})
		}
		for j := 0; j < len(folder.Subfolders); j++ {
			showMyLevel(folder.Subfolders[j], depth+1, tmp)
		}
	}
}

// Creates hierarchial file tree structure
func (m *model) buildVisible() {
	m.VisibleItems = []VisibleItem{}
	showMyLevel(m.root, 0, &m.VisibleItems)
}

func (m *model) showTree() string {
	var basic strings.Builder
	var mark string
	var arrow string
	for i := 0; i < len(m.VisibleItems); i++ {
		object := m.VisibleItems[i]
		spaces := strings.Repeat("  ", object.Depth)

		if object.isFolder {
			mark = "/"
		} else {
			mark = " "
		}
		if i == m.cursor {
			arrow = ">"
		} else {
			arrow = " "
		}

		basic.WriteString(arrow + spaces + mark + object.Name + "\n")
	}
	return basic.String()
}

func initialModel(received <-chan message_manager.TuiMessage,
	sender chan<- message_manager.TuiMessage,
	users []networking.Peer) *model {
	return &model{
		root: message_manager.TUIFolder{
			Name:     "root",
			Path:     "root",
			Hash:     handler.Hash{},
			Loaded:   false,
			Expanded: false,
		},
		users:        users,
		state:        CHOOSE_USER,
		tuiSender:    sender,
		tuiReceiver:  received,
		initialState: true,
	}

}

func findFolder(folder *message_manager.TUIFolder, path string) *message_manager.TUIFolder {
	searchingFolder := (*message_manager.TUIFolder)(nil)
	if folder.Path == path {
		return folder
	}
	for i := 0; i < len(folder.Subfolders); i++ {

		result := findFolder(&folder.Subfolders[i], path)
		if result != nil {
			searchingFolder = result
		}
	}
	return searchingFolder
}

// Receives external data and updates internal states
func (m *model) manageOutsideInfo(message message_manager.TuiMessage) {
	switch message.RequestType() {

	case message_manager.FOLDER_TUI:
		data := message.Payload().(message_manager.TUIFolder)
		folder := findFolder(&m.root, data.Path)
		if folder != nil {
			folder.Files = data.Files
			folder.Subfolders = data.Subfolders
			folder.Loaded = true
			m.buildVisible()
		}
		m.state = FOLDER

	case message_manager.FILE_TUI:
		file := message.Payload().(handler.File)
		m.infoOutside = "Succesfully downloaded " + file.Name + " to directory: " + file.Path

	case message_manager.PEERS_TUI:

		peers := message.Payload().([]networking.Peer)
		if !m.initialState {
			m.infoOutside = "Refreshed the content"
		}

		m.state = CHOOSE_USER
		m.initialState = false
		m.cursor = 0
		m.users = peers
		m.selectedUser = networking.Peer{}
		m.VisibleItems = nil

	case message_manager.CONNECT:
		peer := (message.Payload().([]networking.Peer)[0])
		m.updateUserState(peer)
		m.selectedUser.Stage = networking.CONNECT
		m.infoOutside = "Successful connected with " + peer.Name

	case message_manager.INFO_TUI:
		data := message.Payload().([]string)
		if len(data) > 0 {
			m.infoOutside = data[0]
		}

	case message_manager.ERROR_TUI:
		data := message.Payload().([]string)
		if len(data) > 0 {
			var basic strings.Builder
			for i := range data {
				basic.WriteString(data[i] + "\n")
			}

			m.errorOutside = basic.String()
		}
	}
}

func waitForOutsideInfo(receiver <-chan message_manager.TuiMessage) tea.Cmd {
	return func() tea.Msg {
		data := <-receiver
		return data
	}

}
func (m model) Init() tea.Cmd {
	return waitForOutsideInfo(m.tuiReceiver)
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	switch msg := msg.(type) {
	case message_manager.TuiMessage:
		m.manageOutsideInfo(msg)
		return m, waitForOutsideInfo(m.tuiReceiver)

	case tea.KeyMsg:
		m.infoOutside = ""
		m.errorOutside = ""
		switch msg.String() {
		case "ctrl+c", "q":
			switch m.state {
			case CHOOSE_USER:
				return m, tea.Quit

			case FOLDER:
				m.state = USER_INFO
				m.cursor = 0
				return m, nil

			case USER_INFO:
				m.selectedUser = networking.Peer{}
				m.state = CHOOSE_USER
				m.cursor = 0
			}

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.state == FOLDER && m.cursor < len(m.VisibleItems)-1 {
				m.cursor++
			}
			if m.state == CHOOSE_USER && m.cursor < len(m.users)-1 {
				m.cursor++
			}
		case "c":
			if m.state == USER_INFO {
				m.selectedUser = m.users[m.cursor]
				m.tuiSender <- message_manager.InitConnectionMessage(m.selectedUser)
			}
		case "d":
			if m.state == USER_INFO && m.selectedUser.Stage == networking.CONNECT {
				m.selectedUser = m.users[m.cursor]
				m.cursor = 0
				m.tuiSender <- message_manager.InitGetDataMessage(m.selectedUser)
			}
		case "r":
			m.tuiSender <- message_manager.ReloadContent()

		case "enter":
			switch m.state {

			case CHOOSE_USER:
				m.selectedUser = m.users[m.cursor]
				m.state = USER_INFO
				return m, nil
			case FOLDER:
				item := m.VisibleItems[m.cursor]
				if item.isFolder {
					folder := findFolder(&m.root, item.Path)
					if folder == nil {
						break
					}

					if folder.Expanded {
						folder.Expanded = false
						m.buildVisible()
						break
					}
					if !folder.Loaded {
						folder.Expanded = true
						m.tuiSender <- message_manager.ExpandFolder(folder.Path, m.selectedUser, folder.Name, folder.Hash)
					} else {
						folder.Expanded = true
						m.buildVisible()
					}
				} else {
					m.infoOutside = "Start downloading" + item.Name
					m.tuiSender <- message_manager.DownloadFile(item.Hash, m.selectedUser)
				}
				return m, nil
			}
		}
		return m, nil
	}
	return m, nil
}

func (m *model) View() string {
	s := ""
	switch m.state {
	case CHOOSE_USER:
		s += "Press enter to display information about user \n"
		for i, user := range m.users {

			cursor := " "

			if i == m.cursor {
				cursor = ">"
			}

			s += fmt.Sprintf("%s %s\n", cursor, user.Name)
		}
	case USER_INFO:
		s += fmt.Sprintf("Name: %s\nAddresses:\n", m.selectedUser.Name)
		for _, addr := range m.selectedUser.Addresses {
			s += fmt.Sprintf("  %s\n", addr)
		}
		if m.selectedUser.Stage == networking.CONNECT {
			s += "\nPress [d] to display data"
		} else {
			s += "\nPress [c] to connect"
		}
	case FOLDER:
		s += m.showTree()
	}

	s += "\nPress [r] to resfresh context"
	if m.state == FOLDER {
		s += "\nPress [q] to return to the peer information screen\n"
	}
	if m.state == USER_INFO {
		s += "\nPress [q] to return to the list of peers\n"
	}
	if m.state == CHOOSE_USER {
		s += "\nPress [q] to quit\n"
	}

	if m.infoOutside != "" {
		s += "\n" + "INFO: " + m.infoOutside + "\n"
	}

	if m.errorOutside != "" {
		s += "\n" + "ERROR:" + m.errorOutside + "\n"
	}

	return s
}

func TuiManager(received <-chan message_manager.TuiMessage,
	sender chan<- message_manager.TuiMessage,
	users []networking.Peer) {

	p := tea.NewProgram(initialModel(received, sender, users))
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
