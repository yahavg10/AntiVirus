import axios from 'axios';

export function FileUpload()
{


  onClickHandler = () => {
    const data = new FormData()
   data.append('file', this.state.selectedFile)
   axios.post("http://localhost:8000/upload", data, { 
      // receive two    parameter endpoint url ,form data
  };



    return(<div className="App">
    <form>
      <input type="file" id="myFile" name="filename"/>
      <input type="submit" onClick={this.onFileUpload}/>
    </form>
  </div>);
}