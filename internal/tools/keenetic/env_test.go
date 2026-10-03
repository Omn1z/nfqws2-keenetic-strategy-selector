package keenetic

import (
	"reflect"
	"testing"
)

func TestNativeEnvReplacesEntwareLoaderWithoutChangingParent(t *testing.T) {
	parent := []string{"PATH=/opt/bin:/bin", "LD_LIBRARY_PATH=/opt/lib:/lib", "HOME=/opt/root", "LD_PRELOAD=/opt/lib/preload.so", "LANG=ru_RU.UTF-8", "LD_LIBRARY_PATH=/opt/usr/lib", "OTHER=a=b"}
	before := append([]string(nil), parent...)
	want := []string{"PATH=/opt/bin:/bin", "HOME=/opt/root", "LANG=ru_RU.UTF-8", "OTHER=a=b", "LD_LIBRARY_PATH=/lib:/usr/lib"}
	got := NativeEnv(parent)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("child environment=%v, want %v", got, want)
	}
	got[0] = "changed"
	if !reflect.DeepEqual(parent, before) {
		t.Fatal("native child altered the parent environment")
	}
}

func TestNativeEnvHandlesEmptyAndAlreadyNativeEnvironment(t *testing.T) {
	for _, parent := range [][]string{nil, {"LD_PRELOAD="}, {"LD_LIBRARY_PATH=/lib:/usr/lib"}} {
		if got := NativeEnv(parent); !reflect.DeepEqual(got, []string{"LD_LIBRARY_PATH=/lib:/usr/lib"}) {
			t.Fatalf("native environment=%v", got)
		}
	}
}
