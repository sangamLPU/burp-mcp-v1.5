import burp.api.montoya.MontoyaApi;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Offline-only shape and load-safety checks. No native factory/seed is invoked. */
public final class ControlledScannerSeedTest {
    static void check(boolean value){if(!value)throw new AssertionError();}
    @SuppressWarnings("unchecked") static <T>T proxy(Class<T> type,List<String> calls){
        return (T)Proxy.newProxyInstance(type.getClassLoader(),new Class<?>[]{type},(object,method,args)->{
            calls.add(type.getSimpleName()+"."+method.getName());
            String name=method.getName();
            if(type==MontoyaApi.class&&(name.equals("extension")||name.equals("userInterface")))return proxy(method.getReturnType(),calls);
            if(name.equals("setName")||name.equals("registerSuiteTab"))return null;
            throw new AssertionError("Initialization attempted forbidden API: "+name);
        });
    }
    public static void main(String[] args){
        var defs=ControlledScannerSeed.definitions();
        check(defs.size()==3);
        check(defs.stream().map(d->d.marker()).distinct().count()==3);
        check(defs.stream().filter(d->d.root().startsWith(ControlledScannerSeed.ALLOWED)).count()==2);
        check(defs.stream().filter(d->d.root().equals(ControlledScannerSeed.EXCLUDED)).count()==1);
        check(defs.get(0).attachments().size()==2&&defs.get(0).attachments().stream().anyMatch(a->a.path().equals("/")));
        check(defs.stream().allMatch(d->d.root().startsWith("http://127.0.0.1:8000/")));
        List<String> calls=new ArrayList<>();
        new ControlledScannerSeed().initialize(proxy(MontoyaApi.class,calls));
        check(calls.equals(List.of("MontoyaApi.extension","Extension.setName","MontoyaApi.userInterface","UserInterface.registerSuiteTab")));
        System.out.println("PASS: 7 offline seed-shape/load-safety assertions; initialization performed no finding read/add, scan or HTTP request.");
    }
}
