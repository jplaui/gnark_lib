## sha2 16kB output, latest alpha 0.9.0
go run main.go -debug -sha2 -byte-size 16384 -iterations 1 -backend groth16 (main)gnark_lib
{"level":"debug","time":1692927063,"message":"Debugging activated."}
{"level":"debug","time":1692927063,"message":"EvaluateSha2"}
03:31:03 INF compiling circuit
03:31:03 INF parsed circuit inputs nbPublic=32 nbSecret=16384
03:31:21 INF building constraint builder nbConstraints=5227338
{"level":"debug","elapsed":"17.620282375s","time":1692927081,"message":"compile constraint system time."}
{"level":"debug","written":"1083673813","time":1692927086,"message":"compiled constraint system bytes"}
{"level":"debug","elapsed":"9m4.900520791s","time":1692927646,"message":"groth16.Setup time."}
{"level":"debug","written":"1432007918","time":1692927649,"message":"prover key bytes"}
{"level":"debug","written":"1516","time":1692927649,"message":"verifier key bytes"}
03:40:53 DBG constraint system solver done nbConstraints=5227338 took=3936.622375
03:41:09 DBG prover done backend=groth16 curve=bn254 nbConstraints=5227338 took=16035.022667
{"level":"debug","elapsed":"19.971888708s","time":1692927669,"message":"groth16.Prove time."}
{"level":"debug","written":"128","time":1692927669,"message":"proof bytes"}
{"level":"debug","written":"129","time":1692927669,"message":"witness bytes"}
03:41:09 DBG verifier done backend=groth16 curve=bn254 took=1.865208
{"level":"debug","elapsed":"1.884667ms","time":1692927669,"message":"groth16.Verify time."}

