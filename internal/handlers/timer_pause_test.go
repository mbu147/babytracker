package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/mbentancour/babytracker/internal/middleware"
	"github.com/mbentancour/babytracker/internal/models"
)

// mkWriter creates a user with write access to `child` for sleep and feeding.
func mkWriter(t *testing.T, db *sqlx.DB, child int) int {
	t.Helper()
	role := mkRole(t, db, "writer")
	grantPerm(t, db, role, "sleep", "write")
	grantPerm(t, db, role, "feeding", "write")
	user := mkUser(t, db, "writer", false)
	grantChild(t, db, user, child, role)
	return user
}

// timerAction drives TimersHandler.Pause/Resume as `userID` for timer `id`.
func timerAction(t *testing.T, fn http.HandlerFunc, userID, id int) *httptest.ResponseRecorder {
	t.Helper()
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.Itoa(id))
	req := httptest.NewRequest(http.MethodPost, "/api/timers/"+strconv.Itoa(id)+"/x/", nil)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	rec := httptest.NewRecorder()
	fn(rec, req.WithContext(ctx))
	return rec
}

// createSleepFromTimer posts {child, timer} to SleepHandler.Create the way
// the entry form does when saving a running or paused timer.
func createSleepFromTimer(t *testing.T, h *SleepHandler, userID, childID, timerID int) (models.Sleep, *httptest.ResponseRecorder) {
	t.Helper()
	body := fmt.Sprintf(`{"child":%d,"timer":%d}`, childID, timerID)
	req := httptest.NewRequest(http.MethodPost, "/api/sleep/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID)
	rec := httptest.NewRecorder()
	h.Create(rec, req.WithContext(ctx))
	var s models.Sleep
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
			t.Fatalf("decode sleep: %v", err)
		}
	}
	return s, rec
}

func durationSeconds(t *testing.T, db *sqlx.DB, sleepID int) int {
	t.Helper()
	var secs float64
	if err := db.Get(&secs, `SELECT EXTRACT(EPOCH FROM duration) FROM sleep WHERE id = $1`, sleepID); err != nil {
		t.Fatalf("read duration: %v", err)
	}
	return int(secs)
}

func within(got, want, tolerance int) bool {
	d := got - want
	return d >= -tolerance && d <= tolerance
}

// A timer with a completed 10-minute pause, saved while running: the entry
// keeps the real end, records 600 paused seconds, and its duration excludes
// them.
func TestSleepFromTimerExcludesCompletedPause(t *testing.T) {
	db := setupDB(t)
	child := mkChild(t, db, "Pia")
	now := time.Now()
	var timerID int
	err := db.Get(&timerID, `
		INSERT INTO timers (child_id, name, start_time, is_paused, pauses)
		VALUES ($1, 'sleep', $2, false, jsonb_build_array(jsonb_build_object('start', to_jsonb($3::timestamptz), 'end', to_jsonb($4::timestamptz))))
		RETURNING id`,
		child, now.Add(-30*time.Minute), now.Add(-20*time.Minute), now.Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("insert timer: %v", err)
	}

	s, rec := createSleepFromTimer(t, NewSleepHandler(db), mkWriter(t, db, child), child, timerID)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create sleep: %d %s", rec.Code, rec.Body.String())
	}
	if !within(s.PausedSeconds, 600, 2) {
		t.Errorf("paused_seconds = %d, want ~600", s.PausedSeconds)
	}
	if !within(int(time.Since(s.End).Seconds()), 0, 5) {
		t.Errorf("end = %v, want ~now (%v)", s.End, now)
	}
	if got := durationSeconds(t, db, s.ID); !within(got, 20*60, 3) {
		t.Errorf("duration = %ds, want ~1200s (30 min minus 10 min paused)", got)
	}
}

// Saved while still paused: the open pause counts up to the save moment.
func TestSleepFromTimerCountsOpenPause(t *testing.T) {
	db := setupDB(t)
	child := mkChild(t, db, "Pia")
	now := time.Now()
	var timerID int
	err := db.Get(&timerID, `
		INSERT INTO timers (child_id, name, start_time, is_paused, pauses)
		VALUES ($1, 'sleep', $2, true, jsonb_build_array(jsonb_build_object('start', to_jsonb($3::timestamptz), 'end', 'null'::jsonb)))
		RETURNING id`,
		child, now.Add(-30*time.Minute), now.Add(-5*time.Minute))
	if err != nil {
		t.Fatalf("insert timer: %v", err)
	}

	s, rec := createSleepFromTimer(t, NewSleepHandler(db), mkWriter(t, db, child), child, timerID)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create sleep: %d %s", rec.Code, rec.Body.String())
	}
	if !within(s.PausedSeconds, 300, 2) {
		t.Errorf("paused_seconds = %d, want ~300", s.PausedSeconds)
	}
	if got := durationSeconds(t, db, s.ID); !within(got, 25*60, 3) {
		t.Errorf("duration = %ds, want ~1500s (30 min minus 5 min open pause)", got)
	}
}

// End to end through the Pause and Resume handlers (the JSON the SQL writes
// must round-trip through models.Timer), then a save.
func TestSleepFromTimerViaPauseResumeHandlers(t *testing.T) {
	db := setupDB(t)
	child := mkChild(t, db, "Pia")
	user := mkWriter(t, db, child)
	th := NewTimersHandler(db)
	tm := models.Timer{ChildID: child, Name: "sleep", Start: time.Now().Add(-10 * time.Minute)}
	if err := models.CreateTimer(db, &tm); err != nil {
		t.Fatalf("create timer: %v", err)
	}

	if rec := timerAction(t, th.Pause, user, tm.ID); rec.Code != http.StatusOK {
		t.Fatalf("pause: %d %s", rec.Code, rec.Body.String())
	}
	if rec := timerAction(t, th.Pause, user, tm.ID); rec.Code != http.StatusConflict {
		t.Fatalf("second pause should be 409, got %d %s", rec.Code, rec.Body.String())
	}
	time.Sleep(2100 * time.Millisecond)
	rec := timerAction(t, th.Resume, user, tm.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("resume: %d %s", rec.Code, rec.Body.String())
	}
	var resumed models.Timer
	if err := json.Unmarshal(rec.Body.Bytes(), &resumed); err != nil {
		t.Fatalf("decode resume: %v", err)
	}
	if resumed.IsPaused || len(resumed.Pauses) != 1 || resumed.Pauses[0].Start == nil || resumed.Pauses[0].End == nil {
		t.Fatalf("resume payload wrong: %s", rec.Body.String())
	}

	s, rec2 := createSleepFromTimer(t, NewSleepHandler(db), user, child, tm.ID)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("create sleep: %d %s", rec2.Code, rec2.Body.String())
	}
	if !within(s.PausedSeconds, 2, 1) {
		t.Errorf("paused_seconds = %d, want ~2", s.PausedSeconds)
	}
	if got := durationSeconds(t, db, s.ID); !within(got, 10*60-2, 3) {
		t.Errorf("duration = %ds, want ~598s", got)
	}
	var n int
	if err := db.Get(&n, `SELECT count(*) FROM timers WHERE id = $1`, tm.ID); err != nil || n != 0 {
		t.Errorf("timer should be consumed, count=%d err=%v", n, err)
	}
}
